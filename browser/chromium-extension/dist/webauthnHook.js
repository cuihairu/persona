"use strict";
/**
 * Persona WebAuthn interception — injected into the MAIN world (see
 * manifest.json) before any page script runs.
 *
 * Replaces navigator.credentials.create/get with wrappers that route the
 * ceremony through the Persona native bridge when the user picks a Persona
 * passkey, and fall back to the original browser implementation otherwise
 * (user cancel, no candidates, conditional mediation, cross-origin iframe,
 * or any internal error — the site's native flow is never blocked).
 *
 * This file must stay self-contained: content scripts are classic scripts
 * and cannot use ES module imports.
 */
(() => {
    const win = window;
    if (win.__personaWebauthnHook)
        return;
    win.__personaWebauthnHook = true;
    const MESSAGE_SOURCE = 'persona-webauthn';
    const CONTENT_SOURCE = 'persona-webauthn-content';
    // ============ b64url helpers (duplicated on purpose: no imports) ============
    function bytesToB64url(bytes) {
        let binary = '';
        for (const b of bytes)
            binary += String.fromCharCode(b);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
    function b64urlToBytes(b64url) {
        const padded = b64url
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(Math.ceil(b64url.length / 4) * 4, '=');
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
    function toBytes(source) {
        if (source === undefined || source === null)
            return undefined;
        if (source instanceof ArrayBuffer)
            return new Uint8Array(source);
        return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    }
    // ============ bridge messages (must match BRIDGE_PROTOCOL.md v2) ============
    function creationOptionsToJson(options) {
        const json = {
            rp: { id: options.rp.id ?? undefined, name: options.rp.name ?? undefined },
            user: {
                id: bytesToB64url(toBytes(options.user.id)),
                name: options.user.name,
                displayName: options.user.displayName ?? undefined
            },
            challenge: bytesToB64url(toBytes(options.challenge)),
            pubKeyCredParams: Array.from(options.pubKeyCredParams ?? []).map((p) => ({
                type: p.type,
                alg: p.alg
            })),
            timeout: options.timeout ?? undefined,
            authenticatorSelection: options.authenticatorSelection
                ? {
                    userVerification: options.authenticatorSelection.userVerification ?? undefined,
                    residentKey: options.authenticatorSelection.residentKey ?? undefined,
                    requireResidentKey: options.authenticatorSelection.requireResidentKey ?? undefined
                }
                : undefined,
            excludeCredentials: options.excludeCredentials
                ? Array.from(options.excludeCredentials).map((c) => ({
                    type: c.type,
                    id: bytesToB64url(toBytes(c.id))
                }))
                : undefined,
            attestation: options.attestation ?? undefined
        };
        for (const key of Object.keys(json)) {
            if (json[key] === undefined)
                delete json[key];
        }
        return json;
    }
    /**
     * clientDataJSON the authenticator signs over. Built locally because the
     * hook acts as the authenticator; the bridge only hashes these bytes.
     */
    function clientDataJson(type, challenge) {
        return new TextEncoder().encode(JSON.stringify({
            type,
            challenge: bytesToB64url(challenge),
            origin: location.origin,
            crossOrigin: false
        }));
    }
    function shouldIntercept(options) {
        // Conditional mediation shows the browser's own autofill UI — leave it alone.
        if (options.mediation === 'conditional')
            return false;
        // WebAuthn in cross-origin iframes is out of scope (the spec restricts it anyway).
        if (window.self !== window.top)
            return false;
        // Persona only implements passwordless ceremonies.
        if (!options.publicKey)
            return false;
        return true;
    }
    function userGesture() {
        return Boolean(navigator.userActivation?.isActive);
    }
    const pending = new Map();
    let requestSeq = 0;
    function newRequestId() {
        requestSeq += 1;
        return `persona-${Date.now()}-${requestSeq}`;
    }
    window.addEventListener('message', (event) => {
        if (event.source !== window)
            return;
        const data = event.data;
        if (!data || data.source !== CONTENT_SOURCE)
            return;
        const call = pending.get(data.requestId);
        if (!call)
            return;
        pending.delete(data.requestId);
        detachAbort(call);
        if (data.type === 'PERSONA_PASSKEY_FALLBACK') {
            // User cancelled or Persona has nothing to offer — native flow.
            call.resolve(undefined);
            return;
        }
        if (data.type === 'PERSONA_PASSKEY_DISMISS') {
            call.reject(new DOMException('The user aborted the request.', 'AbortError'));
            return;
        }
        if (data.ok) {
            call.resolve(data.data);
        }
        else {
            call.reject(new DOMException(data.error ?? 'Persona passkey error', 'NotAllowedError'));
        }
    });
    function detachAbort(call) {
        if (call.signal && call.abortHandler) {
            call.signal.removeEventListener('abort', call.abortHandler);
        }
    }
    function watchAbort(signal, onAbort) {
        if (!signal)
            return;
        signal.addEventListener('abort', onAbort, { once: true });
    }
    /** Ask the content script to run the UI + bridge round-trip. */
    function askContent(type, payload, signal) {
        return new Promise((resolve, reject) => {
            const requestId = newRequestId();
            const call = { resolve, reject, signal };
            pending.set(requestId, call);
            watchAbort(signal, () => {
                if (!pending.has(requestId))
                    return;
                pending.delete(requestId);
                window.postMessage({ source: MESSAGE_SOURCE, type: 'PERSONA_PASSKEY_CANCEL', requestId }, location.origin);
                reject(new DOMException('The user aborted the request.', 'AbortError'));
            });
            window.setTimeout(() => {
                if (pending.has(requestId)) {
                    pending.delete(requestId);
                    detachAbort(call);
                    reject(new DOMException('Persona passkey request timed out', 'NotAllowedError'));
                }
            }, 5 * 60 * 1000);
            window.postMessage({ source: MESSAGE_SOURCE, type, requestId, payload }, location.origin);
        });
    }
    // ============ response assembly ============
    function makeCreationCredential(payload) {
        const rawId = b64urlToBytes(payload.credential_id_b64);
        const clientDataJSON = b64urlToBytes(payload.client_data_json_b64);
        const attestationObject = b64urlToBytes(payload.attestation_object_b64);
        return {
            id: payload.credential_id_b64,
            rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.byteLength),
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: clientDataJSON.buffer.slice(clientDataJSON.byteOffset, clientDataJSON.byteOffset + clientDataJSON.byteLength),
                attestationObject: attestationObject.buffer.slice(attestationObject.byteOffset, attestationObject.byteOffset + attestationObject.byteLength),
                getTransports: () => Promise.resolve(payload.transports ?? ['internal']),
                getPublicKey: () => Promise.resolve(null),
                getPublicKeyAlgorithm: () => -7,
                getAuthenticatorData: () => null
            },
            getClientExtensionResults: () => ({})
        };
    }
    function makeAssertionCredential(payload, clientDataJSON) {
        const rawId = b64urlToBytes(payload.credential_id_b64);
        const authenticatorData = b64urlToBytes(payload.authenticator_data_b64);
        const signature = b64urlToBytes(payload.signature_der_b64);
        const userHandle = b64urlToBytes(payload.user_handle_b64);
        return {
            id: payload.credential_id_b64,
            rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.byteLength),
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: clientDataJSON.buffer.slice(clientDataJSON.byteOffset, clientDataJSON.byteOffset + clientDataJSON.byteLength),
                authenticatorData: authenticatorData.buffer.slice(authenticatorData.byteOffset, authenticatorData.byteOffset + authenticatorData.byteLength),
                signature: signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength),
                userHandle: userHandle.byteLength
                    ? userHandle.buffer.slice(userHandle.byteOffset, userHandle.byteOffset + userHandle.byteLength)
                    : null
            },
            getClientExtensionResults: () => ({})
        };
    }
    // ============ intercepted entry points ============
    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.create = async (options) => {
        try {
            if (!options || !shouldIntercept(options)) {
                return (await originalCreate(options));
            }
            const publicKey = options.publicKey;
            const challenge = toBytes(publicKey.challenge);
            const payload = await askContent('PERSONA_PASSKEY_CREATE', {
                origin: location.origin,
                user_gesture: userGesture(),
                request_json: creationOptionsToJson(publicKey),
                client_data_json_b64: bytesToB64url(clientDataJson('webauthn.create', challenge))
            }, options.signal);
            // undefined = user cancelled the confirm dialog → native flow.
            if (!payload)
                return originalCreate(options);
            return makeCreationCredential(payload);
        }
        catch (error) {
            if (error?.name === 'AbortError')
                throw error;
            // Persona unavailable — native flow.
            return originalCreate(options);
        }
    };
    navigator.credentials.get = async (options) => {
        try {
            if (!options || !shouldIntercept(options)) {
                return (await originalGet(options));
            }
            const publicKey = options.publicKey;
            const challenge = toBytes(publicKey.challenge);
            const clientData = clientDataJson('webauthn.get', challenge);
            const payload = await askContent('PERSONA_PASSKEY_GET', {
                origin: location.origin,
                user_gesture: userGesture(),
                rp_id: publicKey.rpId ?? undefined,
                client_data_json_b64: bytesToB64url(clientData),
                user_verification: (publicKey.userVerification ?? 'preferred') !== 'discouraged'
            }, options.signal);
            // undefined = no candidates or the user dismissed the picker → native.
            if (!payload)
                return originalGet(options);
            return makeAssertionCredential(payload, clientData);
        }
        catch (error) {
            if (error?.name === 'AbortError')
                throw error;
            return originalGet(options);
        }
    };
    console.debug('[Persona] WebAuthn hook installed');
})();
//# sourceMappingURL=webauthnHook.js.map