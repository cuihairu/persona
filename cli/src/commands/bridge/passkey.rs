use super::*;

/// Shared body of `passkey_list` and `passkey_credential_provider_list`:
/// identical semantics and validation chain, differing only in the message
/// kind used for logs and the response type.
pub(super) async fn run_passkey_list(
    db_path: &Path,
    request_id: Option<String>,
    parsed: PasskeyListPayload,
    kind: &str,
) -> Result<BridgeResponse<serde_json::Value>> {
    if gesture_required() && !parsed.user_gesture {
        warn!(origin = %parsed.origin, "{kind} rejected: user_gesture required");
        return Err(anyhow!(
            "user_gesture_required: passkey enumeration requires user action"
        ));
    }

    let rp_id = match &parsed.rp_id {
        Some(rp_id) => {
            validate_origin_matches_rp_id(&parsed.origin, rp_id)
                .map_err(|_| anyhow!("passkey_rp_mismatch: rp_id does not match request origin"))?;
            rp_id.clone()
        }
        None => origin_to_host(&parsed.origin)?,
    };

    let (service, _) = open_unlocked_service(db_path).await?;
    let passkeys = service.list_passkeys_by_rp(&rp_id).await?;
    let mut items = Vec::with_capacity(passkeys.len());
    for pk in passkeys {
        let identity_name = service.get_identity(&pk.identity_id).await?.map(|i| i.name);
        items.push(PasskeyListItem {
            id: pk.id.to_string(),
            rp_id: pk.rp_id,
            user_name: pk.user_name,
            user_display_name: pk.user_display_name,
            identity_name,
            created_at: pk.created_at.timestamp(),
        });
    }
    debug!(event = "bridge_passkey_list", kind, rp_id = %rp_id, count = items.len());

    Ok(ok(
        request_id,
        &format!("{kind}_response"),
        serde_json::json!({ "items": items, "rp_id": rp_id }),
    ))
}

/// Shared body of `passkey_assert` and `passkey_credential_provider_assert`.
/// `gate_op` names the desktop-approval operation shown in the confirmation
/// dialog; `via` lands in the audit metadata so the trust path
/// (browser extension vs OS passkey provider) stays distinguishable.
pub(super) async fn run_passkey_assert(
    db_path: &Path,
    request_id: Option<String>,
    parsed: PasskeyAssertPayload,
    gate_op: &'static str,
    via: &'static str,
) -> Result<BridgeResponse<serde_json::Value>> {
    let kind = if via == "os_provider" {
        "passkey_credential_provider_assert"
    } else {
        "passkey_assert"
    };

    if gesture_required() && !parsed.user_gesture {
        warn!(origin = %parsed.origin, "{kind} rejected: user_gesture required");
        return Err(anyhow!(
            "user_gesture_required: passkey assertions require an explicit selection click"
        ));
    }

    // Second consent line: a running desktop must approve before
    // anything is signed. rp_id/user_name live on the stored item;
    // the desktop dialog shows origin + item id.
    match desktop_approval_gate(gate_op, None, &parsed.origin, None, Some(&parsed.item_id)).await? {
        #[cfg(unix)]
        DesktopApproval::Approved => {}
        #[cfg(unix)]
        DesktopApproval::Denied(reason) => {
            warn!(origin = %parsed.origin, %reason, "{kind} denied by desktop");
            return Err(anyhow!(
                "passkey_desktop_denied: assertion rejected by desktop approval ({reason})"
            ));
        }
        DesktopApproval::Unavailable => {}
    }

    let item_id = uuid::Uuid::parse_str(&parsed.item_id)
        .map_err(|e| anyhow!("invalid_request: item_id uuid: {e}"))?;
    let client_data_json = URL_SAFE_NO_PAD
        .decode(parsed.client_data_json_b64.as_bytes())
        .context("invalid_request: client_data_json_b64 must be base64url")?;

    let (service, active_identity_id) = open_unlocked_service(db_path).await?;

    // Preflight the item so error codes stay precise; the assertion
    // re-validates origin↔rp_id inside core regardless.
    let item = service
        .get_passkey(&item_id)
        .await?
        .ok_or_else(|| anyhow!("passkey_item_not_found"))?;
    if let Some(active) = active_identity_id {
        if item.identity_id != active {
            return Err(anyhow!(
                "wrong_identity: switch active identity to use this passkey"
            ));
        }
    }
    validate_origin_matches_rp_id(&parsed.origin, &item.rp_id)
        .map_err(|_| anyhow!("passkey_rp_mismatch: origin does not match the passkey's rp_id"))?;

    let assertion = service
        .passkey_assertion(
            &item_id,
            &parsed.origin,
            &client_data_json,
            parsed.user_verification,
            via,
        )
        .await
        .map_err(|e| {
            let not_found = e
                .downcast_ref::<PersonaError>()
                .is_some_and(|pe| matches!(pe, PersonaError::NotFound(_)));
            if not_found {
                anyhow!("passkey_item_not_found")
            } else {
                anyhow!("passkey_assert_failed: {e}")
            }
        })?;

    info!(
        event = "bridge_passkey_assert",
        kind,
        via,
        rp_id = %item.rp_id,
        origin = %parsed.origin,
        item_id = %item.id,
        user_gesture = parsed.user_gesture,
        "passkey assertion signed via bridge"
    );

    Ok(ok(
        request_id,
        &format!("{kind}_response"),
        serde_json::to_value(PasskeyAssertResponse {
            item_id: item.id.to_string(),
            credential_id_b64: URL_SAFE_NO_PAD.encode(&assertion.credential_id),
            authenticator_data_b64: URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            signature_der_b64: URL_SAFE_NO_PAD.encode(&assertion.signature_der),
            user_handle_b64: URL_SAFE_NO_PAD.encode(&assertion.user_handle),
        })?,
    ))
}
