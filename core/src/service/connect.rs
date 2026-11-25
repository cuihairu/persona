use super::*;

impl PersonaService {
    /// Throttle window for Connect auditing and `last_used` persistence (at most once per key per 60s).
    pub(crate) const CONNECT_THROTTLE: Duration = Duration::from_secs(60);

    /// Throttle table capacity cap: keys of the form `unknown:{fingerprint}` are driven by the
    /// caller's token, and every randomly forged token is unique, so an unbounded table could let
    /// memory grow without limit (audit batch 2 #7).
    /// When over the cap, expired entries are purged first to make room; if still full, this
    /// mark is dropped (false = no audit written) — the flood self-limits and the table length
    /// is capped; throttling for keys already in the window is unaffected.
    pub(crate) const CONNECT_THROTTLE_MARKS_MAX: usize = 4096;

    /// Lock gate: the Connect data plane is only available in an unlocked session (DR-4; the
    /// endpoint layer maps [`PersonaError::VaultLocked`] to 503).
    pub(crate) fn connect_gate(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::VaultLocked(
                "connect endpoint requires an unlocked vault".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// Same-key throttling: returns false if already written within the window, otherwise
    /// refreshes the window and allows the write.
    /// In-memory state, cleared on process restart — prevents log spam/bulk writes, not an
    /// access rate limit.
    /// Table length is capped at [`Self::CONNECT_THROTTLE_MARKS_MAX`]: unique fingerprints from
    /// unknown-token floods are no longer inserted (and no audit is written for them), so memory
    /// does not grow with request volume.
    pub(crate) fn connect_throttle_should_write(&self, key: &str) -> bool {
        let mut marks = self.connect_audit_marks.lock().unwrap();
        let now = Instant::now();
        match marks.get(key) {
            Some(t) if now.duration_since(*t) < Self::CONNECT_THROTTLE => false,
            _ => {
                if marks.len() >= Self::CONNECT_THROTTLE_MARKS_MAX {
                    marks.retain(|_, t| now.duration_since(*t) < Self::CONNECT_THROTTLE);
                    if marks.len() >= Self::CONNECT_THROTTLE_MARKS_MAX {
                        return false;
                    }
                }
                marks.insert(key.to_string(), now);
                true
            }
        }
    }

    /// Create a Connect token: returns `(presented plaintext, db row)` — the plaintext is shown
    /// only this once; the caller (desktop settings page/CLI) owns the "cannot be viewed again
    /// after closing" semantics.
    /// `principal` binds the caller identity (empty/whitespace normalized to `None`); `expires_at`
    /// = `None` means never expires (legacy data semantics). Management operations go through the
    /// sensitive gate (reauth) + unlocked session (DR-5).
    pub async fn create_connect_token(
        &self,
        label: String,
        scope: ConnectTokenScope,
        principal: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(String, ConnectTokenRow)> {
        self.ensure_sensitive_operation_allowed().await?;
        self.connect_gate()?;
        scope
            .validate()
            .map_err(|e| PersonaError::InvalidInput(format!("invalid connect scope: {e}")))
            .map_err(anyhow::Error::from)?;
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 128 {
            return Err(PersonaError::InvalidInput(
                "connect token label must be 1..=128 characters".to_string(),
            )
            .into());
        }
        let principal = principal
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty());
        if principal
            .as_deref()
            .is_some_and(|p| p.chars().count() > 256)
        {
            return Err(PersonaError::InvalidInput(
                "connect token principal must be at most 256 characters".to_string(),
            )
            .into());
        }
        if expires_at.is_some_and(|t| t <= chrono::Utc::now()) {
            return Err(PersonaError::InvalidInput(
                "connect token expiry must be in the future".to_string(),
            )
            .into());
        }

        let presented = crate::connect::generate_token();
        let hash = crate::connect::hash_token(&presented).ok_or_else(|| {
            PersonaError::CryptographicError("connect token hash failed".to_string())
        })?;
        let row = ConnectTokenRow {
            id: Uuid::new_v4(),
            label: label.to_string(),
            fingerprint: crate::connect::fingerprint_from_hash(&hash),
            hash,
            scope,
            principal,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
            expires_at,
        };
        ConnectTokenRepository::new(self.db.clone())
            .insert(&row)
            .await?;

        self.log_audit(
            AuditAction::ConnectTokenCreated,
            ResourceType::Connect,
            true,
            Some(row.id),
            None,
            None,
        )
        .await;

        Ok((presented, row))
    }

    /// Token management listing (includes revoked; the admin surface shows revocation status).
    /// Rows contain hashes — the caller strips them during serialization (desktop/CLI show only
    /// label/fingerprint/scope/timestamps).
    pub async fn list_connect_tokens(&self) -> Result<Vec<ConnectTokenRow>> {
        self.connect_gate()?;
        Ok(ConnectTokenRepository::new(self.db.clone())
            .list_all()
            .await?)
    }

    /// Revoke (idempotent: repeated revocation returns false). Takes effect immediately — auth
    /// looks up the table on every request, with no cache window (DR-2). Management operations go
    /// through the sensitive gate (reauth) + unlocked session.
    pub async fn revoke_connect_token(&self, id: &Uuid) -> Result<bool> {
        self.ensure_sensitive_operation_allowed().await?;
        self.connect_gate()?;
        let revoked = ConnectTokenRepository::new(self.db.clone())
            .revoke(id, chrono::Utc::now())
            .await?;
        if revoked {
            self.log_audit(
                AuditAction::ConnectTokenRevoked,
                ResourceType::Connect,
                true,
                Some(*id),
                None,
                None,
            )
            .await;
        }
        Ok(revoked)
    }

    /// Per-request auth: presented value → SHA-256 → table lookup → revocation check. On a hit,
    /// throttled persistence of `last_used_at` and throttled audit (so automated polls don't spam
    /// the log); attempts with unknown/revoked tokens also write throttled failure audits (keyed
    /// by fingerprint prefix — auditable without spam).
    pub async fn connect_authenticate(&self, presented: &str) -> Result<Option<ConnectTokenRow>> {
        let Some(hash) = crate::connect::hash_token(presented) else {
            return Ok(None);
        };
        let repo = ConnectTokenRepository::new(self.db.clone());
        let Some(row) = repo.find_by_hash(&hash).await? else {
            let fp = crate::connect::fingerprint_from_hash(&hash);
            if self.connect_throttle_should_write(&format!("unknown:{fp}")) {
                self.log_audit(
                    AuditAction::ConnectTokenUsed,
                    ResourceType::Connect,
                    false,
                    None,
                    None,
                    Some(format!("unknown token {fp}")),
                )
                .await;
            }
            return Ok(None);
        };
        if row.revoked() {
            if self.connect_throttle_should_write(&format!("revoked:{}", row.id)) {
                self.log_audit(
                    AuditAction::ConnectTokenUsed,
                    ResourceType::Connect,
                    false,
                    Some(row.id),
                    None,
                    Some("revoked token".to_string()),
                )
                .await;
            }
            return Ok(None);
        }
        // Expired tokens are rejected in the same shape as revoked ones (migration 019: expires_at check).
        if row.expired() {
            if self.connect_throttle_should_write(&format!("expired:{}", row.id)) {
                self.log_audit(
                    AuditAction::ConnectTokenUsed,
                    ResourceType::Connect,
                    false,
                    Some(row.id),
                    None,
                    Some("expired token".to_string()),
                )
                .await;
            }
            return Ok(None);
        }
        if self.connect_throttle_should_write(&format!("used:{}", row.id)) {
            repo.touch_last_used(&row.id, chrono::Utc::now()).await?;
            self.log_audit(
                AuditAction::ConnectTokenUsed,
                ResourceType::Connect,
                true,
                Some(row.id),
                None,
                None,
            )
            .await;
        }
        Ok(Some(row))
    }

    /// 404-shaped mapping for token read decisions: the unified authorization entry treats Denied
    /// as `false`, and the endpoint layer maps it to an empty list/None (same shape as a 404, so
    /// existence is not leaked).
    pub(crate) fn token_allows_read(principal: &AuthzPrincipal, resource: &AuthzResource) -> bool {
        authorize(
            principal,
            resource,
            AuthzAction::Read,
            &AuthzContext::CONNECT,
        )
        .is_allowed()
    }

    /// Scope-denial auditing (completed in architecture correction batch 2): previously scope
    /// denials were not audited at all. Throttled persistence (same window as used/unknown),
    /// recording the token fingerprint and denial point, so automated polls don't spam the log;
    /// per-row filtering within a list is normal noise reduction and is not recorded per row.
    pub(crate) async fn audit_scope_denied(&self, token: &ConnectTokenRow, detail: &str) {
        if self.connect_throttle_should_write(&format!("denied:{}", token.id)) {
            // A token id is not an identity/credential FK: the log is built directly carrying only
            // resource_id (same policy as deletion events), bypassing log_audit's FK arm.
            let log = AuditLog::new(
                AuditAction::UnauthorizedAccess,
                ResourceType::Connect,
                false,
            )
            .with_user_id(self.current_user.map(|u| u.to_string()))
            .with_resource_id(Some(token.id.to_string()))
            .with_error_message(Some(format!(
                "scope denied ({}): {detail}",
                token.fingerprint
            )));
            let _ = self.audit_repo.create(&log).await;
        }
    }

    /// Identity list within scope (id + name).
    pub async fn connect_list_identities(&self, token: &ConnectTokenRow) -> Result<Vec<Identity>> {
        self.connect_gate()?;
        let principal = AuthzPrincipal::ConnectToken {
            scope: token.scope.clone(),
        };
        if !Self::token_allows_read(&principal, &AuthzResource::Vault) {
            self.audit_scope_denied(token, "list identities: read not granted")
                .await;
            return Ok(vec![]);
        }
        let all = self.get_identities().await?;
        Ok(all
            .into_iter()
            .filter(|i| Self::token_allows_read(&principal, &AuthzResource::Identity { id: i.id }))
            .collect())
    }

    /// Item metadata within scope. `?identity=`/`?type=`/`?title=` filter exactly;
    /// an identity parameter outside scope returns an empty list (no error, to prevent probing).
    pub async fn connect_list_items(
        &self,
        token: &ConnectTokenRow,
        identity: Option<Uuid>,
        item_type: Option<ConnectItemType>,
        title: Option<String>,
    ) -> Result<Vec<Credential>> {
        self.connect_gate()?;
        let principal = AuthzPrincipal::ConnectToken {
            scope: token.scope.clone(),
        };
        if !Self::token_allows_read(&principal, &AuthzResource::Vault) {
            self.audit_scope_denied(token, "list items: read not granted")
                .await;
            return Ok(vec![]);
        }
        if let Some(want) = &identity {
            if !Self::token_allows_read(&principal, &AuthzResource::Identity { id: *want }) {
                self.audit_scope_denied(token, "list items: identity param outside scope")
                    .await;
                return Ok(vec![]);
            }
        }
        let all = Repository::find_all(&self.credential_repo).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.is_active)
            .filter(|c| identity.as_ref().is_none_or(|want| &c.identity_id == want))
            .filter(|c| {
                Self::token_allows_read(
                    &principal,
                    &AuthzResource::Credential {
                        identity_id: c.identity_id,
                        credential_type: c.credential_type.clone(),
                    },
                )
            })
            .filter(|c| {
                item_type.is_none_or(|want| {
                    ConnectItemType::from_credential_type(&c.credential_type) == Some(want)
                })
            })
            .filter(|c| title.as_ref().is_none_or(|t| &c.name == t))
            .collect())
    }

    /// A single item's full fields (after decryption). Out-of-scope/archived/nonexistent all
    /// yield `None` — the endpoint layer maps them uniformly to 404 (same shape as 403).
    pub async fn connect_get_item_data(
        &self,
        token: &ConnectTokenRow,
        id: &Uuid,
    ) -> Result<Option<(Credential, CredentialData)>> {
        self.connect_gate()?;
        let principal = AuthzPrincipal::ConnectToken {
            scope: token.scope.clone(),
        };
        if !Self::token_allows_read(&principal, &AuthzResource::Vault) {
            self.audit_scope_denied(token, "get item data: read not granted")
                .await;
            return Ok(None);
        }
        let Some(cred) = self.get_credential(id).await? else {
            return Ok(None);
        };
        if !cred.is_active {
            return Ok(None);
        }
        if !Self::token_allows_read(
            &principal,
            &AuthzResource::Credential {
                identity_id: cred.identity_id,
                credential_type: cred.credential_type.clone(),
            },
        ) {
            self.audit_scope_denied(token, "get item data: credential outside scope")
                .await;
            return Ok(None);
        }
        let Some(data) = self.get_credential_data(id).await? else {
            return Ok(None);
        };
        Ok(Some((cred, data)))
    }

    /// Current TOTP code + seconds remaining (reuses the core RFC 6238 path; out-of-scope/non-
    /// TwoFactor all yield `None`).
    pub async fn connect_totp(
        &self,
        token: &ConnectTokenRow,
        id: &Uuid,
    ) -> Result<Option<crate::crypto::totp::TotpCode>> {
        self.connect_gate()?;
        let principal = AuthzPrincipal::ConnectToken {
            scope: token.scope.clone(),
        };
        if !Self::token_allows_read(&principal, &AuthzResource::Vault) {
            self.audit_scope_denied(token, "totp: read not granted")
                .await;
            return Ok(None);
        }
        let Some(cred) = self.get_credential(id).await? else {
            return Ok(None);
        };
        // A single decision covers both the identity and type dimensions; for non-TwoFactor items
        // the subsequent data gate (`CredentialData::TwoFactor`) likewise yields None.
        if !cred.is_active {
            return Ok(None);
        }
        if !Self::token_allows_read(
            &principal,
            &AuthzResource::Credential {
                identity_id: cred.identity_id,
                credential_type: cred.credential_type.clone(),
            },
        ) {
            self.audit_scope_denied(token, "totp: credential outside scope")
                .await;
            return Ok(None);
        }
        let Some(data) = self.get_credential_data(id).await? else {
            return Ok(None);
        };
        let CredentialData::TwoFactor(tf) = data else {
            return Ok(None);
        };
        Ok(Some(crate::crypto::totp::totp_now(&tf)?))
    }
}
