use super::*;

impl PersonaService {
    /// Connect 审计与 last_used 落库节流窗口（同 key 每 60s 至多一次）。
    pub(crate) const CONNECT_THROTTLE: Duration = Duration::from_secs(60);

    /// 锁定门禁：Connect 数据面只在解锁会话内可用（DR-4；端点层把
    /// [`PersonaError::VaultLocked`] 映射为 503）。
    pub(crate) fn connect_gate(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::VaultLocked(
                "connect endpoint requires an unlocked vault".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// 同 key 节流：窗口内已写过则 false，否则刷新窗口并放行。
    /// 内存态，进程重启即清——防刷屏/批量写，不是访问限额。
    pub(crate) fn connect_throttle_should_write(&self, key: &str) -> bool {
        let mut marks = self.connect_audit_marks.lock().unwrap();
        let now = Instant::now();
        match marks.get(key) {
            Some(t) if now.duration_since(*t) < Self::CONNECT_THROTTLE => false,
            _ => {
                marks.insert(key.to_string(), now);
                true
            }
        }
    }

    /// 创建 Connect token：返回 `(presented 明文, 库行)`——明文仅此一次
    /// 展示，调用方（桌面设置页/CLI）负责「关闭后无法再次查看」语义。
    /// `principal` 绑定调用方身份（空/空白归一为 `None`）；`expires_at`
    /// 为 `None` = 永不过期（旧数据语义）。管理操作走敏感门禁（reauth）
    /// + 解锁会话（DR-5）。
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

    /// Token 管理列表（含已吊销，管理面展示吊销状态）。行含哈希——调用方
    /// 序列化时剥除（桌面/CLI 都只展示 label/指纹/scope/时间戳）。
    pub async fn list_connect_tokens(&self) -> Result<Vec<ConnectTokenRow>> {
        self.connect_gate()?;
        Ok(ConnectTokenRepository::new(self.db.clone())
            .list_all()
            .await?)
    }

    /// 吊销（幂等：重复吊销返回 false）。即时生效——鉴权每请求查表，
    /// 无缓存窗口（DR-2）。管理操作走敏感门禁（reauth）+ 解锁会话。
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

    /// 每请求鉴权：呈现值 → SHA-256 → 查表 → 吊销判定。命中即节流落库
    /// `last_used_at` 并节流记审计（自动化轮询不刷屏）；未知/吊销 token
    /// 的尝试也节流记失败审计（指纹前缀做 key，可审计但不刷屏）。
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
        // 过期 token 与吊销同形拒绝（迁移 019：expires_at 判定）。
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

    /// token 读裁决的 404 形映射：统一授权入口判 Denied → `false`，
    /// 端点层映射空列表/None（与 404 同形，不泄露存在性）。
    pub(crate) fn token_allows_read(principal: &AuthzPrincipal, resource: &AuthzResource) -> bool {
        authorize(
            principal,
            resource,
            AuthzAction::Read,
            &AuthzContext::CONNECT,
        )
        .is_allowed()
    }

    /// scope 拒绝审计（架构校正批2 补全）：此前 scope 拒绝零审计。节流
    /// 落库（与 used/unknown 同窗口），记 token 指纹与拒绝点，自动化
    /// 轮询不刷屏；列表内逐条过滤属正常降噪行为，不逐条记。
    pub(crate) async fn audit_scope_denied(&self, token: &ConnectTokenRow, detail: &str) {
        if self.connect_throttle_should_write(&format!("denied:{}", token.id)) {
            // token id 不是 identity/credential 外键：直构日志只载
            // resource_id（与删除事件同策略），不走 log_audit 的外键臂。
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

    /// scope 内身份列表（id + 名称）。
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

    /// scope 内条目元数据。`?identity=`/`?type=`/`?title=` 精确过滤；
    /// identity 参数越 scope 返回空列表（不报错，防探测）。
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

    /// 单条全字段（解密后）。scope 外/归档/不存在一律 `None`——端点层
    /// 统一映射 404（与 403 同形）。
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

    /// 当前 TOTP 码 + 剩余秒（复用 core RFC 6238 路径；scope 外/非
    /// TwoFactor 一律 `None`）。
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
        // 单条裁决涵盖身份与类型两维；非 TwoFactor 条目随后的数据门
        // （`CredentialData::TwoFactor`）同形 None。
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
