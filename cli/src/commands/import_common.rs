//! 导入命令共享的落库逻辑：把确认过的 [`ImportPlan`] 应用到 workspace。
//!
//! `import-1pux` 与 `import-generic` 用同一套"建/复用身份 → 建凭据 →
//! 补呈现字段"的流程，保证两条导入路径的身份复用与失败中止语义一致。

use std::collections::HashMap;

use anyhow::{Context, Result};
use uuid::Uuid;

use persona_core::import_1pux::{ImportPlan, PlannedCredential};
use persona_core::models::{Identity, IdentityType};
use persona_core::PersonaService;

pub(crate) struct ApplySummary {
    pub imported: usize,
    pub identities_created: usize,
    pub identities_reused: usize,
}

/// Apply a confirmed plan: create/reuse identities, then credentials.
///
/// Same-name identities are reused (reported, never duplicated); the whole
/// run aborts on the first failure so a partial import can simply be re-run.
/// `identity_kind` 进身份类型（`IdentityType::Custom`），`container_kind`
/// 出现在复用日志里（如 "1Password vault"）。
pub(crate) async fn apply_plan(
    service: &PersonaService,
    plan: &ImportPlan,
    identity_kind: &str,
    container_kind: &str,
) -> Result<ApplySummary> {
    let mut vault_to_identity: HashMap<String, Uuid> = HashMap::new();
    let mut identities_created = 0;
    let mut identities_reused = 0;

    for planned in &plan.identities {
        let identity = match service.get_identity_by_name(&planned.name).await? {
            Some(existing) => {
                println!(
                    "Reusing existing identity '{}' for {} {}",
                    planned.name, container_kind, planned.vault_uuid
                );
                identities_reused += 1;
                existing
            }
            None => {
                let mut identity = Identity::new(
                    planned.name.clone(),
                    IdentityType::Custom(identity_kind.to_string()),
                );
                identity.description = Some(planned.description.clone());
                identities_created += 1;
                service
                    .create_identity_full(identity)
                    .await
                    .with_context(|| format!("Failed to create identity '{}'", planned.name))?
            }
        };
        vault_to_identity.insert(planned.vault_uuid.clone(), identity.id);
    }

    let mut imported = 0;
    for planned in &plan.credentials {
        let identity_id = vault_to_identity
            .get(&planned.vault_uuid)
            .with_context(|| format!("No identity mapped for vault {}", planned.vault_uuid))?;
        import_credential(service, *identity_id, planned).await?;
        imported += 1;
    }

    Ok(ApplySummary {
        imported,
        identities_created,
        identities_reused,
    })
}

async fn import_credential(
    service: &PersonaService,
    identity_id: Uuid,
    planned: &PlannedCredential,
) -> Result<()> {
    // create_credential only fills the encrypted payload; presentation
    // fields are patched on and persisted with update_credential (same
    // pattern as the desktop create flows).
    let mut credential = service
        .create_credential(
            identity_id,
            planned.name.clone(),
            planned.credential_type.clone(),
            planned.security_level.clone(),
            &planned.credential_data,
        )
        .await
        .with_context(|| format!("Failed to create credential '{}'", planned.name))?;

    credential.url = planned.url.clone();
    credential.username = planned.username.clone();
    credential.notes = planned.notes.clone();
    credential.tags = planned.tags.clone();
    credential.metadata = planned.metadata.clone();
    credential.is_favorite = planned.is_favorite;

    service
        .update_credential(&credential)
        .await
        .with_context(|| format!("Failed to finalize credential '{}'", planned.name))?;
    Ok(())
}
