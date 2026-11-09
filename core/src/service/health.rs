use super::*;

impl PersonaService {
    /// Run a Watchtower-style vault health scan (offline rules only).
    ///
    /// See [`Self::scan_health_with`] for the breach-check-enabled variant.
    pub async fn scan_health(&self, config: HealthScanConfig) -> Result<HealthReport> {
        self.scan_health_with(config, None).await
    }

    /// Run a Watchtower-style vault health scan.
    ///
    /// Decrypts every credential in memory, evaluates the offline rules
    /// (weak/reused secrets, expiries, staleness) and — when a
    /// [`BreachChecker`] is supplied — the breach rule. The checker works on
    /// SHA-1 digests only; plaintext secrets never reach it, and nothing
    /// leaves the call frame. A checker failure downgrades to a warning and
    /// the offline rules still report. One aggregate
    /// `SecurityScanPerformed` audit entry is written (`breach_status`:
    /// `skipped` / `completed` / `unavailable`).
    pub async fn scan_health_with(
        &self,
        config: HealthScanConfig,
        breach: Option<&dyn BreachChecker>,
    ) -> Result<HealthReport> {
        self.ensure_unlocked_with_auto_lock().await?;

        let credentials = self.credential_repo.find_all().await?;
        let now = chrono::Utc::now();

        // Secret material collected for the weak/reuse rules; dropped when
        // the scan frame ends.
        let mut secrets_by_password: HashMap<String, Vec<Uuid>> = HashMap::new();
        // credential_id → (name, type) so issues can be attributed later
        // without holding decrypted data.
        let mut secrets: HashMap<Uuid, (String, String, String)> = HashMap::new();
        // 2FA-available rule inputs: Password credentials carrying a site
        // URL, and the site keys already covered by TOTP-like credentials.
        let mut login_urls: Vec<(Uuid, String, String, String)> = Vec::new();
        let mut totp_sites: std::collections::HashSet<String> = std::collections::HashSet::new();

        let mut issues: Vec<HealthIssue> = Vec::new();
        let mut push_issue = |credential: &Credential, kind: HealthIssueKind| {
            issues.push(HealthIssue {
                credential_id: credential.id,
                credential_name: credential.name.clone(),
                credential_type: credential.credential_type.to_string(),
                severity: kind.severity(),
                detail: kind.detail(),
                kind,
            });
        };

        for credential in &credentials {
            if !credential.is_active {
                continue;
            }

            // Expiry rules (no decryption needed)
            let data = match self.decrypt_credential(credential) {
                Ok(data) => data,
                // A credential that fails to decrypt is reported but must
                // not abort the whole scan.
                Err(e) => {
                    tracing::warn!("health scan: failed to decrypt {}: {e}", credential.id);
                    continue;
                }
            };

            match &data {
                CredentialData::ApiKey(api) => {
                    if let Some(expires_at) = api.expires_at {
                        if let Some(kind) =
                            crate::health::check_expiry(expires_at, now, config.expiry_warning_days)
                        {
                            push_issue(credential, kind);
                        }
                    }
                }
                CredentialData::BankCard(card) => {
                    if let Some(kind) = crate::health::check_bank_card_expiry(
                        &card.expiry_date,
                        now,
                        config.expiry_warning_days,
                    ) {
                        push_issue(credential, kind);
                    }
                }
                CredentialData::SoftwareLicense(lic) => {
                    // `valid_until` is free text; unparseable values are
                    // skipped (data quality, not a security finding).
                    if let Some(valid_until) = &lic.valid_until {
                        if let Some(kind) = crate::health::check_text_expiry(
                            valid_until,
                            now,
                            config.expiry_warning_days,
                        ) {
                            push_issue(credential, kind);
                        }
                    }
                }
                _ => {}
            }

            // 2FA-available rule inputs: which logins have a site URL, and
            // which sites already have a TOTP-like credential.
            match &data {
                CredentialData::TwoFactor(_) | CredentialData::GameToken(_) => {
                    if let Some(site) = credential
                        .url
                        .as_deref()
                        .and_then(crate::health::normalize_site_key)
                    {
                        totp_sites.insert(site);
                    }
                }
                CredentialData::Password(_) => {
                    if let Some(url) = credential.url.as_deref() {
                        if crate::health::normalize_site_key(url).is_some() {
                            login_urls.push((
                                credential.id,
                                credential.name.clone(),
                                credential.credential_type.to_string(),
                                url.to_string(),
                            ));
                        }
                    }
                }
                _ => {}
            }

            // Staleness rule (metadata only)
            if let Some(kind) =
                crate::health::check_stale(credential.updated_at, now, config.stale_after_days)
            {
                push_issue(credential, kind);
            }

            // Secret strength + reuse rules
            let secret: Option<&str> = match &data {
                CredentialData::Password(p) => Some(p.password.as_str()),
                CredentialData::ServerConfig(s) => s.password.as_deref(),
                CredentialData::SshKey(k) => k.passphrase.as_deref(),
                _ => None,
            };
            if let Some(secret) = secret {
                let (score, _suggestions) = crate::health::evaluate_password_strength(secret);
                if score < config.min_password_score {
                    push_issue(credential, HealthIssueKind::WeakPassword { score });
                }
                secrets_by_password
                    .entry(secret.to_string())
                    .or_default()
                    .push(credential.id);
                secrets.insert(
                    credential.id,
                    (
                        credential.name.clone(),
                        credential.credential_type.to_string(),
                        String::new(),
                    ),
                );
            }
        }

        // 2FA-available rule (1Password Watchtower "2FA available"):
        // directory sites with no TOTP-like credential covering them.
        for (credential_id, name, credential_type, url) in &login_urls {
            if let Some(site) = crate::health::check_two_factor_available(url, &totp_sites) {
                let kind = HealthIssueKind::TwoFactorAvailable { site };
                issues.push(HealthIssue {
                    credential_id: *credential_id,
                    credential_name: name.clone(),
                    credential_type: credential_type.clone(),
                    severity: kind.severity(),
                    detail: kind.detail(),
                    kind,
                });
            }
        }

        // Reuse rule: one issue per credential in any shared group.
        for group in crate::health::find_reused_groups(&secrets_by_password) {
            let group_size = group.len();
            for credential_id in group {
                let (name, credential_type, _) = secrets[&credential_id].clone();
                let kind = HealthIssueKind::ReusedPassword { group_size };
                issues.push(HealthIssue {
                    credential_id,
                    credential_name: name,
                    credential_type,
                    severity: kind.severity(),
                    detail: kind.detail(),
                    kind,
                });
            }
        }

        // Breach rule: consult the corpus through SHA-1 digests only.
        // Failure is not fatal — the offline rules above already reported.
        let (breach_status, breach_checked): (&str, usize) = match breach {
            None => ("skipped", 0),
            Some(checker) => {
                // One digest per distinct secret; duplicate digests (hash
                // collisions) are harmless — the checker dedupes by prefix.
                let digest_of: HashMap<&String, String> = secrets_by_password
                    .keys()
                    .map(|secret| (secret, crate::breach::sha1_hex_upper(secret)))
                    .collect();
                let digests: Vec<String> = digest_of.values().cloned().collect();
                match checker.breach_counts(&digests).await {
                    Ok(counts) => {
                        for (secret, credential_ids) in &secrets_by_password {
                            let count = counts.get(&digest_of[secret]).copied().unwrap_or(0);
                            if count == 0 {
                                continue;
                            }
                            let kind = HealthIssueKind::BreachedPassword { count };
                            for credential_id in credential_ids {
                                let (name, credential_type, _) = secrets[credential_id].clone();
                                issues.push(HealthIssue {
                                    credential_id: *credential_id,
                                    credential_name: name,
                                    credential_type,
                                    severity: kind.severity(),
                                    detail: kind.detail(),
                                    kind: kind.clone(),
                                });
                            }
                        }
                        ("completed", digests.len())
                    }
                    Err(e) => {
                        tracing::warn!("health scan: breach check unavailable: {e}");
                        ("unavailable", 0)
                    }
                }
            }
        };

        let report = HealthReport::finalize(now, credentials.len(), issues);

        // One aggregate audit entry; the report itself is not persisted and
        // contains no secret material.
        let audit = AuditLog::new(
            AuditAction::SecurityScanPerformed,
            ResourceType::System,
            true,
        )
        .with_metadata(
            "total_credentials".to_string(),
            report.total_credentials.to_string(),
        )
        .with_metadata("issue_count".to_string(), report.issues.len().to_string())
        .with_metadata("breach_checked".to_string(), breach_checked.to_string())
        .with_metadata("breach_status".to_string(), breach_status.to_string());
        let _ = self.audit_repo.create(&audit).await;

        Ok(report)
    }
}
