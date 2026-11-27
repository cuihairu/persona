/**
 * manifest contract tests: three hard rules of the MV3 wiring.
 *
 * 1. webauthnHook (MAIN world) is injected in the top frame only: wrapping every
 *    third-party iframe with a navigator.credentials shim is far too invasive, and passkeys
 *    in cross-origin iframes fall back to the browser's native flow anyway (a design decision, see README).
 *    This assertion stops someone casually flipping all_frames.
 * 2. content.js covers every frame (including about:blank/srcdoc) — the batch B iframe login
 *    autofill depends on it.
 * 3. content.js must stay in the ISOLATED world (omitting the world field is the default) — the
 *    MAIN world can reach anything the page script can.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

interface ContentScriptEntry {
    matches?: string[];
    js?: string[];
    run_at?: string;
    world?: string;
    all_frames?: boolean;
    match_about_blank?: boolean;
}

interface Manifest {
    manifest_version: number;
    version: string;
    permissions?: string[];
    background?: { service_worker?: string; type?: string };
    action?: { default_popup?: string };
    content_scripts?: ContentScriptEntry[];
}

const manifest: Manifest = JSON.parse(
    readFileSync(join(__dirname, '..', 'manifest.json'), 'utf8')
);

function entryFor(file: string): ContentScriptEntry {
    const entry = manifest.content_scripts?.find((candidate) =>
        candidate.js?.some((script) => script.endsWith(file))
    );
    if (!entry) throw new Error(`no content_scripts entry injects ${file}`);
    return entry;
}

describe('manifest — webauthn hook (passkey interception)', () => {
    it('runs in the MAIN world at document_start, top frame only', () => {
        const entry = entryFor('webauthnHook.js');
        expect(entry.world).toBe('MAIN');
        expect(entry.run_at).toBe('document_start');
        expect(entry.all_frames).toBe(false);
    });

    it('matches all urls so the top-frame ceremony is always interceptable', () => {
        expect(entryFor('webauthnHook.js').matches).toContain('<all_urls>');
    });
});

describe('manifest — content script (autofill + save bar)', () => {
    it('covers every frame, including about:blank/srcdoc frames', () => {
        const entry = entryFor('content.js');
        expect(entry.all_frames).toBe(true);
        expect(entry.match_about_blank).toBe(true);
    });

    it('stays in the ISOLATED world at document_idle', () => {
        const entry = entryFor('content.js');
        expect(entry.world).toBeUndefined();
        expect(entry.run_at).toBe('document_idle');
    });

    it('matches all urls', () => {
        expect(entryFor('content.js').matches).toContain('<all_urls>');
    });
});

describe('manifest — host wiring', () => {
    it('is MV3 with the module service worker and the native-messaging permission', () => {
        expect(manifest.manifest_version).toBe(3);
        expect(manifest.background?.service_worker).toBe('dist/background.js');
        expect(manifest.background?.type).toBe('module');
        expect(manifest.permissions).toEqual(
            expect.arrayContaining(['nativeMessaging', 'storage', 'scripting', 'activeTab'])
        );
    });

    it('keeps the action popup wired', () => {
        expect(manifest.action?.default_popup).toBe('public/popup.html');
    });
});