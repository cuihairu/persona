use super::*;

impl PersonaService {
    /// Create a new identity
    pub async fn create_identity(
        &self,
        name: String,
        identity_type: IdentityType,
    ) -> Result<Identity> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.touch_activity();
        self.update_auto_lock_activity().await?;

        let identity = Identity::new(name, identity_type);
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        )
        .await;
        Ok(created)
    }

    /// Create a new identity with all fields pre-populated.
    /// Use this when the caller already collected metadata such as email/phone/tags.
    pub async fn create_identity_full(&self, mut identity: Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Ensure timestamps are reasonable and updated on create
        identity.touch();
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        )
        .await;
        Ok(created)
    }

    /// Get all identities
    pub async fn get_identities(&self) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.identity_repo.find_all().await
    }

    /// Get identity by name
    pub async fn get_identity_by_name(&self, name: &str) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let res = self.identity_repo.find_by_name(name).await?;
        if let Some(ref ident) = res {
            self.log_audit(
                AuditAction::IdentityViewed,
                ResourceType::Identity,
                true,
                Some(ident.id),
                None,
                None,
            )
            .await;
        }
        Ok(res)
    }

    /// Get identity by ID
    pub async fn get_identity(&self, id: &Uuid) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let res = self.identity_repo.find_by_id(id).await?;
        if let Some(ref ident) = res {
            self.log_audit(
                AuditAction::IdentityViewed,
                ResourceType::Identity,
                true,
                Some(ident.id),
                None,
                None,
            )
            .await;
        }
        Ok(res)
    }

    /// Update an identity
    pub async fn update_identity(&self, identity: &Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let updated = self.identity_repo.update(identity).await?;
        self.log_audit(
            AuditAction::IdentityUpdated,
            ResourceType::Identity,
            true,
            Some(updated.id),
            None,
            None,
        )
        .await;
        Ok(updated)
    }

    /// Delete an identity
    pub async fn delete_identity(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Audit logs reference identities via a strict FK; detach them first so the identity can
        // be deleted while preserving the audit trail.
        let _ = self.audit_repo.clear_identity_reference(id).await?;
        let ok = self.identity_repo.delete(id).await?;
        self.log_audit(
            AuditAction::IdentityDeleted,
            ResourceType::Identity,
            ok,
            Some(*id),
            None,
            None,
        )
        .await;
        Ok(ok)
    }

    /// Get identities by type
    pub async fn get_identities_by_type(
        &self,
        identity_type: &IdentityType,
    ) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.identity_repo.find_by_type(identity_type).await
    }
}
