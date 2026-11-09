use super::*;

/// Export data structure for backup
#[derive(Debug)]
pub struct IdentityExport {
    pub identity: Identity,
    pub credentials: Vec<Credential>,
}

/// Service usage statistics
#[derive(Debug)]
pub struct PersonaStatistics {
    pub total_identities: usize,
    pub total_credentials: usize,
    pub active_credentials: usize,
    pub favorite_credentials: usize,
    pub credential_types: HashMap<String, u32>,
    pub security_levels: HashMap<String, u32>,
}

impl PersonaService {
    /// Generate a strong password (legacy helper).
    pub fn generate_password(&self, length: usize, include_symbols: bool) -> String {
        let options = PasswordGeneratorOptions {
            length: length.max(4),
            include_symbols,
            ..Default::default()
        };

        PasswordGenerator::generate(&options).unwrap_or_else(|_| {
            // Fall back to a safe default if option validation fails for any reason.
            PasswordGenerator::generate(&PasswordGeneratorOptions {
                length: 12,
                include_symbols: false,
                ..PasswordGeneratorOptions::default()
            })
            .unwrap_or_else(|_| "persona-temp".to_string())
        })
    }

    /// Generate a password using advanced options.
    pub fn generate_password_with_options(
        &self,
        options: &PasswordGeneratorOptions,
    ) -> Result<String> {
        PasswordGenerator::generate(options)
    }

    /// Generate salt for master key derivation
    pub fn generate_salt(&self) -> [u8; 32] {
        self.master_key_service.generate_salt()
    }

    /// Hash data using SHA-256
    pub fn hash_data(&self, data: &[u8]) -> [u8; 32] {
        Sha256Hasher::hash(data)
    }

    /// Export identity data (for backup)
    pub async fn export_identity(&self, identity_id: &Uuid) -> Result<IdentityExport> {
        self.ensure_unlocked()?;

        let identity = self
            .identity_repo
            .find_by_id(identity_id)
            .await?
            .ok_or_else(|| PersonaError::IdentityNotFound(identity_id.to_string()))?;

        let credentials = self.credential_repo.find_by_identity(identity_id).await?;

        let export = IdentityExport {
            identity,
            credentials,
        };
        self.log_audit(
            AuditAction::BackupCreated,
            ResourceType::Identity,
            true,
            Some(*identity_id),
            None,
            None,
        )
        .await;
        Ok(export)
    }

    /// Get service statistics
    pub async fn get_statistics(&self) -> Result<PersonaStatistics> {
        self.ensure_unlocked()?;

        let identities = self.identity_repo.find_all().await?;
        let all_credentials = self.credential_repo.find_all().await?;

        let mut credential_types: HashMap<String, u32> = HashMap::new();
        let mut security_levels: HashMap<String, u32> = HashMap::new();

        for cred in &all_credentials {
            *credential_types
                .entry(cred.credential_type.to_string())
                .or_insert(0) += 1;
            *security_levels
                .entry(cred.security_level.to_string())
                .or_insert(0) += 1;
        }

        Ok(PersonaStatistics {
            total_identities: identities.len(),
            total_credentials: all_credentials.len(),
            active_credentials: all_credentials.iter().filter(|c| c.is_active).count(),
            favorite_credentials: all_credentials.iter().filter(|c| c.is_favorite).count(),
            credential_types,
            security_levels,
        })
    }
}
