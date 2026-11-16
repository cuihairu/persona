use anyhow::{anyhow, Result};
use persona_core::{
    models::{Credential as CoreCredential, Identity as CoreIdentity},
    storage::{CredentialRepository, IdentityRepository, Repository},
    PersonaService,
};
use uuid::Uuid;

#[allow(clippy::large_enum_variant)]
pub(crate) enum DataProvider {
    Service(PersonaService),
    Direct {
        identity_repo: IdentityRepository,
        credential_repo: CredentialRepository,
    },
}

impl DataProvider {
    pub(super) async fn identities(&mut self) -> Result<Vec<CoreIdentity>> {
        match self {
            DataProvider::Service(service) => service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to load identities: {}", e)),
            DataProvider::Direct { identity_repo, .. } => identity_repo
                .find_all()
                .await
                .map_err(|e| anyhow!("Failed to load identities: {}", e)),
        }
    }

    pub(super) async fn credentials(&mut self, identity_id: &Uuid) -> Result<Vec<CoreCredential>> {
        match self {
            DataProvider::Service(service) => service
                .get_credentials_for_identity(identity_id)
                .await
                .map_err(|e| anyhow!("Failed to load credentials: {}", e)),
            DataProvider::Direct {
                credential_repo, ..
            } => credential_repo
                .find_by_identity(identity_id)
                .await
                .map_err(|e| anyhow!("Failed to load credentials: {}", e)),
        }
    }
}

pub(crate) struct IdentityItem {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) identity_type: String,
    pub(super) tags: Vec<String>,
    pub(super) active: bool,
}

impl From<CoreIdentity> for IdentityItem {
    fn from(value: CoreIdentity) -> Self {
        Self {
            id: value.id,
            name: value.name,
            identity_type: value.identity_type.to_string(),
            tags: value.tags,
            active: value.is_active,
        }
    }
}

pub(crate) struct CredentialItem {
    pub(super) name: String,
    pub(super) credential_type: String,
    pub(super) username: String,
    pub(super) security: String,
    pub(super) updated: String,
}

impl From<CoreCredential> for CredentialItem {
    fn from(value: CoreCredential) -> Self {
        let username = value.username.unwrap_or_else(|| "-".to_string());
        let updated = value.updated_at.format("%Y-%m-%d %H:%M").to_string();
        Self {
            name: value.name,
            credential_type: value.credential_type.to_string(),
            username,
            security: value.security_level.to_string(),
            updated,
        }
    }
}
