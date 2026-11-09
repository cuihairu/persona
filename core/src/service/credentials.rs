use super::*;

impl PersonaService {
    /// Create a new credential
    pub async fn create_credential(
        &self,
        identity_id: Uuid,
        name: String,
        credential_type: CredentialType,
        security_level: SecurityLevel,
        credential_data: &CredentialData,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        // Serialize and encrypt the credential data
        let plaintext = credential_data.to_bytes().map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to serialize credential data: {}", e))
        })?;

        let (envelope, item_key) = hierarchy.encrypt_with_new_item_key_revealed(&plaintext)?;

        let credential = Credential::new(
            identity_id,
            name,
            credential_type,
            security_level,
            envelope.ciphertext,
            Some(envelope.wrapped_key),
        );

        let created = self.credential_repo.create(&credential).await?;
        self.log_audit(
            AuditAction::CredentialCreated,
            ResourceType::Credential,
            true,
            Some(created.id),
            Some(identity_id),
            None,
        )
        .await;
        self.record_credential_history(ChangeType::Created, None, Some(&created), None)
            .await;
        // 同步载荷 = 完整条目快照（元数据 + CredentialData）的密封——与
        // 主库 `encrypted_data` 同一把 item key、两份不同密文（见
        // `sync::snapshot` 模块文档）。密封失败只跳过捕获，不影响主库写入。
        match SyncItemSnapshot::from_credential(&created, credential_data).seal(&item_key) {
            Ok(sealed) => {
                self.capture_sync(
                    created.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(sealed),
                    Some(item_key),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                credential_id = %created.id,
                error = %e,
                "sync snapshot seal failed; capture skipped"
            ),
        }
        Ok(created)
    }

    /// Get credentials for an identity
    pub async fn get_credentials_for_identity(
        &self,
        identity_id: &Uuid,
    ) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_identity(identity_id).await
    }

    /// Get a specific credential by ID
    pub async fn get_credential(&self, id: &Uuid) -> Result<Option<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_id(id).await
    }

    /// 按需抓取凭据 URL 对应站点的 favicon 并入缓存（`favicon` feature）。
    ///
    /// 唯一的外联触发点：由用户在详情面板点击 "Fetch icon" 经命令层调用，
    /// 绝不自动批量抓取。缓存按 host 命中即返，不重复外联。
    /// 不做 audit log——favicon 是公开数据，日志只记 host。
    #[cfg(feature = "favicon")]
    pub async fn fetch_favicon_for_credential(
        &self,
        credential_id: &Uuid,
        fetcher: &crate::favicon::FaviconFetcher,
    ) -> Result<FaviconCacheEntry> {
        use crate::favicon::extract_favicon_host;

        self.ensure_unlocked()?;
        self.touch_activity();

        let credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;

        let url = credential
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| PersonaError::InvalidInput("credential has no url".to_string()))?;

        let host = extract_favicon_host(url)?;

        // 缓存命中即返：缓存 miss 是抓取的必要条件
        if let Some(entry) = self.favicon_repo.get(&host).await? {
            return Ok(entry);
        }

        let blob = fetcher.fetch(&host).await?;
        self.favicon_repo
            .upsert(&host, &blob.mime_type, &blob.data)
            .await?;

        let entry =
            self.favicon_repo.get(&host).await?.ok_or_else(|| {
                PersonaError::Database("favicon upsert did not persist".to_string())
            })?;
        tracing::info!(host = %host, "favicon fetched and cached");
        Ok(entry)
    }

    /// 批量读取已缓存的 favicon（纯本地读，绝不外联）。
    ///
    /// hosts 大小写不敏感去重后逐 host 点查；只返回命中项，调用方以
    /// "缺席 = 无缓存"处理，本方法永远不会触发抓取。
    pub async fn get_cached_favicons(&self, hosts: &[String]) -> Result<Vec<FaviconCacheEntry>> {
        self.ensure_unlocked()?;
        self.touch_activity();

        if hosts.len() > MAX_HOSTS_PER_REQUEST {
            return Err(PersonaError::InvalidInput(format!(
                "too many hosts requested: {} > {MAX_HOSTS_PER_REQUEST}",
                hosts.len()
            ))
            .into());
        }

        let unique: Vec<String> = hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        self.favicon_repo.get_many(&unique).await
    }

    /// Decrypt and get credential data
    pub async fn get_credential_data(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<CredentialData>> {
        self.ensure_authorized(&AuthzResource::Vault, AuthzAction::Read)
            .await?;
        self.touch_activity();

        let credential = match self.credential_repo.find_by_id(credential_id).await? {
            Some(cred) => cred,
            None => return Ok(None),
        };

        // Mark as accessed
        let mut credential = credential;
        credential.mark_accessed();
        self.credential_repo.update(&credential).await?;

        let credential_data = self.decrypt_credential(&credential)?;
        self.log_audit(
            AuditAction::CredentialDecrypted,
            ResourceType::Credential,
            true,
            Some(credential.id),
            Some(credential.identity_id),
            None,
        )
        .await;

        self.update_sensitive_auto_lock_activity().await?;
        Ok(Some(credential_data))
    }

    /// Decrypt a credential's payload without side effects (no access-time
    /// update, no per-credential audit entry, no re-auth gate).
    ///
    /// The gated path is [`Self::get_credential_data`]; batch operations
    /// (health scan) use this one and record a single aggregate audit entry
    /// instead.
    pub(crate) fn decrypt_credential(&self, credential: &Credential) -> Result<CredentialData> {
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        let plaintext = match &credential.wrapped_item_key {
            Some(wrapped_key) => {
                hierarchy.decrypt_with_wrapped_key(wrapped_key, &credential.encrypted_data)?
            }
            None => master_encryption
                .decrypt(&credential.encrypted_data)
                .map_err(|e| {
                    PersonaError::CryptographicError(format!(
                        "Failed to decrypt legacy credential: {}",
                        e
                    ))
                })?,
        };

        let credential_data = CredentialData::from_bytes(&plaintext).map_err(|e| {
            PersonaError::CryptographicError(format!(
                "Failed to deserialize credential data: {}",
                e
            ))
        })?;
        Ok(credential_data)
    }

    /// Update a credential
    pub async fn update_credential(&self, credential: &Credential) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Item history 需要变更前快照做字段级 diff
        let existing = self.credential_repo.find_by_id(&credential.id).await?;
        let updated = self.credential_repo.update(credential).await?;
        if let Some(old) = existing.as_ref() {
            self.record_credential_history(ChangeType::Updated, Some(old), Some(&updated), None)
                .await;
        }
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        // 元数据编辑同样进同步（快照含元数据全字段）；legacy 行由 helper
        // 判定跳过。
        if let Some((sealed, item_key)) = self.sync_put_payload_for(&updated).await {
            self.capture_sync(
                updated.id,
                ItemKind::Credential,
                OpType::Put,
                Some(sealed),
                Some(item_key),
            )
            .await;
        }
        Ok(updated)
    }

    /// Replace a credential's encrypted payload (edit secret data).
    ///
    /// Re-seals the new payload under the credential's **existing** item key —
    /// never a fresh one: attachments are sealed with that same key, so a new
    /// key would render them permanently undecryptable. The row's
    /// `wrapped_item_key` bytes are left untouched. Legacy rows (no wrapped
    /// key) are upgraded to a per-item key on edit, mirroring the attachment
    /// path. Gated like [`Self::get_credential_data`] (editing secret data is
    /// at least as sensitive as reading it) and recorded as an item-history
    /// `Updated` row plus an audit entry.
    pub async fn update_credential_data(
        &self,
        credential_id: &Uuid,
        credential_data: &CredentialData,
    ) -> Result<Credential> {
        self.ensure_authorized(&AuthzResource::Vault, AuthzAction::Use)
            .await?;
        self.touch_activity();

        let mut credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;
        let existing = credential.clone();

        let plaintext = credential_data.to_bytes().map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to serialize credential data: {}", e))
        })?;
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        let (new_ciphertext, new_wrapped_key, sync_item_key) =
            match credential.wrapped_item_key.as_ref() {
                Some(wrapped) => {
                    // 复用原 item key 重封；wrapped key 字节不动（附件不变量）。
                    let item_key = hierarchy.unwrap_item_key(wrapped)?;
                    let ciphertext = hierarchy.encrypt_with_item_key(&item_key, &plaintext)?;
                    (ciphertext, None, Zeroizing::new(item_key))
                }
                None => {
                    // legacy 行（payload 直接用主密钥封存）：编辑时升级为 per-item
                    // key，与附件封存路径同一模式，改密轮换后不再依赖 legacy 解密。
                    let (envelope, item_key) =
                        hierarchy.encrypt_with_new_item_key_revealed(&plaintext)?;
                    (envelope.ciphertext, Some(envelope.wrapped_key), item_key)
                }
            };
        credential.encrypted_data = new_ciphertext;
        if let Some(wrapped) = new_wrapped_key {
            credential.wrapped_item_key = Some(wrapped);
            tracing::info!(credential_id = %credential.id, "legacy credential upgraded to per-item key on edit");
        }
        credential.touch();

        let updated = self.credential_repo.update(&credential).await?;
        self.record_credential_history(ChangeType::Updated, Some(&existing), Some(&updated), None)
            .await;
        // 同步载荷 = 完整条目快照的密封（与 create 同款；同一把 item key）。
        match SyncItemSnapshot::from_credential(&updated, credential_data).seal(&sync_item_key) {
            Ok(sealed) => {
                self.capture_sync(
                    updated.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(sealed),
                    Some(sync_item_key),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                credential_id = %updated.id,
                error = %e,
                "sync snapshot seal failed; capture skipped"
            ),
        }
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        self.update_sensitive_auto_lock_activity().await?;
        Ok(updated)
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Fetch the credential up-front so we can detach audit logs and keep useful context.
        let existing = self.credential_repo.find_by_id(id).await?;
        if existing.is_none() {
            return Ok(false);
        }
        let existing = existing.unwrap();

        let _ = self.audit_repo.clear_credential_reference(id).await?;

        // Cascade-delete attachments: they are sealed under this credential's
        // item key, so orphaned blobs could never be decrypted again.
        if let Some(manager) = self.attachment_manager.as_ref() {
            let attachments = manager.list_for_credential(id).await?;
            for attachment in attachments {
                if let Err(e) = manager.delete(&attachment.id).await {
                    tracing::warn!(
                        attachment_id = %attachment.id,
                        error = %e,
                        "failed to delete attachment during credential deletion"
                    );
                }
            }
        }

        let ok = self.credential_repo.delete(id).await?;
        if ok {
            self.record_credential_history(ChangeType::Deleted, Some(&existing), None, None)
                .await;
            self.capture_sync(*id, ItemKind::Credential, OpType::Delete, None, None)
                .await;
        }
        self.log_audit(
            AuditAction::CredentialDeleted,
            ResourceType::Credential,
            ok,
            Some(*id),
            Some(existing.identity_id),
            None,
        )
        .await;
        Ok(ok)
    }

    /// Restore a credential's plaintext metadata to an earlier item-history version.
    ///
    /// Applies the `new_state` snapshot of `target_version` — the state after
    /// that version's change — over the live row's metadata fields (name, type,
    /// security level, username, url, notes, tags, favorite/active flags).
    ///
    /// The secret payload is **not** versioned: history snapshots are
    /// metadata-only by design (`encrypted_data` never enters a snapshot), so
    /// a restore never rolls back passwords or other `CredentialData` secrets —
    /// rotating a secret stays a forward-only action. Records a `Restored`
    /// item-history row (reason names the target version) plus an audit entry.
    /// Deletion rows carry no `new_state` and are not restorable.
    pub async fn restore_credential_version(
        &self,
        credential_id: &Uuid,
        target_version: u32,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let existing = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;
        let row = self
            .change_history_repo
            .get_version(EntityType::Credential, credential_id, target_version)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!(
                    "credential {credential_id} has no history version {target_version}"
                ))
            })?;
        let snapshot = row.new_state.as_ref().ok_or_else(|| {
            PersonaError::InvalidInput(format!(
                "history version {target_version} has no restorable state"
            ))
        })?;

        let mut restored = existing.clone();
        Self::apply_meta_snapshot(&mut restored, snapshot)?;
        restored.touch();
        let updated = self.credential_repo.update(&restored).await?;
        self.record_credential_history(
            ChangeType::Restored,
            Some(&existing),
            Some(&updated),
            Some(format!("restore to version {target_version}")),
        )
        .await;
        self.log_audit(
            AuditAction::CredentialRestored,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        // 元数据回滚同样改变快照语义字段，进同步（同款 legacy 跳过）。
        if let Some((sealed, item_key)) = self.sync_put_payload_for(&updated).await {
            self.capture_sync(
                updated.id,
                ItemKind::Credential,
                OpType::Put,
                Some(sealed),
                Some(item_key),
            )
            .await;
        }
        Ok(updated)
    }

    /// Search credentials by name / username / url
    pub async fn search_credentials(&self, query: &str) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.search_by_fields(query).await
    }

    /// Get favorite credentials
    pub async fn get_favorite_credentials(&self) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_favorites().await
    }

    /// Get credentials by type
    pub async fn get_credentials_by_type(
        &self,
        credential_type: &CredentialType,
    ) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_type(credential_type).await
    }

    /// Structured custom fields of a credential (1Password parity).
    ///
    /// The field list is sealed under the credential's per-item key and
    /// stored as one `metadata` blob, so this needs an unlocked vault.
    /// A credential without the blob has no custom fields.
    pub async fn custom_fields(&self, credential_id: &Uuid) -> Result<Vec<CustomField>> {
        self.ensure_unlocked()?;
        let credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;
        let Some(blob) = credential.metadata.get(CUSTOM_FIELDS_METADATA_KEY) else {
            return Ok(Vec::new());
        };
        let key = self
            .credential_item_key_for_attachment(credential_id)
            .await?;
        decode_custom_fields(blob, &key)
    }

    /// Replace a credential's structured custom fields (empty list removes
    /// them). Seals under the per-item key into `metadata`, then goes
    /// through the regular update path so item history, audit and sync
    /// capture all see the change.
    pub async fn set_custom_fields(
        &self,
        credential_id: &Uuid,
        fields: Vec<CustomField>,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        let mut credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;

        if fields.is_empty() {
            credential.metadata.remove(CUSTOM_FIELDS_METADATA_KEY);
        } else {
            // Dedup ids so edits stay addressable; labels may repeat.
            let mut seen = std::collections::HashSet::new();
            if !fields.iter().all(|f| seen.insert(f.id.as_str())) {
                return Err(PersonaError::InvalidInput(
                    "custom field ids must be unique".to_string(),
                )
                .into());
            }
            let key = self
                .credential_item_key_for_attachment(credential_id)
                .await?;
            let blob = encode_custom_fields(&fields, &key)?;
            credential
                .metadata
                .insert(CUSTOM_FIELDS_METADATA_KEY.to_string(), blob);
        }

        self.update_credential(&credential).await
    }

    /// Item history（1Password 对齐）：凭据变更快照，只含明文元数据字段。
    /// `encrypted_data` / `wrapped_item_key` 绝不进快照。
    pub(crate) fn credential_meta_snapshot(credential: &Credential) -> serde_json::Value {
        serde_json::json!({
            "name": credential.name,
            "credential_type": credential.credential_type.to_string(),
            "security_level": credential.security_level.to_string(),
            "username": credential.username,
            "url": credential.url,
            "notes": credential.notes,
            "tags": credential.tags,
            "is_favorite": credential.is_favorite,
            "is_active": credential.is_active,
        })
    }

    /// 把 [`Self::credential_meta_snapshot`] 写出的快照套回凭据元数据
    /// （restore-to-version 用）。整份校验通过后才落字段，坏快照不半套；
    /// 秘密字段（`encrypted_data` / `wrapped_item_key`）不在快照里，保持原样。
    pub(crate) fn apply_meta_snapshot(
        credential: &mut Credential,
        snapshot: &serde_json::Value,
    ) -> Result<()> {
        let obj = snapshot.as_object().ok_or_else(|| {
            PersonaError::InvalidInput("history snapshot is not an object".to_string())
        })?;
        let required_str = |key: &str| -> Result<String> {
            obj.get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    PersonaError::InvalidInput(format!("history snapshot missing field {key}"))
                        .into()
                })
        };
        let optional_str = |key: &str| -> Option<String> {
            obj.get(key).and_then(|v| v.as_str()).map(str::to_string)
        };

        let name = required_str("name")?;
        let credential_type = required_str("credential_type")?
            .parse::<CredentialType>()
            .map_err(PersonaError::InvalidInput)?;
        let security_level = required_str("security_level")?
            .parse::<SecurityLevel>()
            .map_err(PersonaError::InvalidInput)?;
        let tags = match obj.get("tags") {
            Some(serde_json::Value::Array(items)) => {
                let mut tags = Vec::with_capacity(items.len());
                for item in items {
                    tags.push(item.as_str().map(str::to_string).ok_or_else(|| {
                        PersonaError::InvalidInput(
                            "history snapshot tag is not a string".to_string(),
                        )
                    })?);
                }
                tags
            }
            _ => {
                return Err(PersonaError::InvalidInput(
                    "history snapshot missing field tags".to_string(),
                )
                .into())
            }
        };
        let is_favorite = obj
            .get("is_favorite")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                PersonaError::InvalidInput("history snapshot missing field is_favorite".to_string())
            })?;
        let is_active = obj
            .get("is_active")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                PersonaError::InvalidInput("history snapshot missing field is_active".to_string())
            })?;

        credential.name = name;
        credential.credential_type = credential_type;
        credential.security_level = security_level;
        credential.username = optional_str("username");
        credential.url = optional_str("url");
        credential.notes = optional_str("notes");
        credential.tags = tags;
        credential.is_favorite = is_favorite;
        credential.is_active = is_active;
        Ok(())
    }

    /// 元数据字段级 diff；密文变化只记占位标记（历史里可见「密码已轮换」
    /// 这一事实，但永远看不到内容——与 1Password 的历史展示一致）。
    pub(crate) fn diff_credential_metadata(
        old: &Credential,
        new: &Credential,
    ) -> Vec<(&'static str, String, String)> {
        let mut changes = Vec::new();
        let mut push = |field: &'static str, o: String, n: String| {
            if o != n {
                changes.push((field, o, n));
            }
        };
        push("name", old.name.clone(), new.name.clone());
        push(
            "credential_type",
            old.credential_type.to_string(),
            new.credential_type.to_string(),
        );
        push(
            "security_level",
            old.security_level.to_string(),
            new.security_level.to_string(),
        );
        push(
            "username",
            old.username.clone().unwrap_or_default(),
            new.username.clone().unwrap_or_default(),
        );
        push(
            "url",
            old.url.clone().unwrap_or_default(),
            new.url.clone().unwrap_or_default(),
        );
        push(
            "notes",
            old.notes.clone().unwrap_or_default(),
            new.notes.clone().unwrap_or_default(),
        );
        push("tags", old.tags.join(","), new.tags.join(","));
        push(
            "is_favorite",
            old.is_favorite.to_string(),
            new.is_favorite.to_string(),
        );
        push(
            "is_active",
            old.is_active.to_string(),
            new.is_active.to_string(),
        );
        if old.encrypted_data != new.encrypted_data {
            changes.push((
                "encrypted_data",
                "<encrypted>".to_string(),
                "<encrypted>".to_string(),
            ));
        }
        changes
    }
}
