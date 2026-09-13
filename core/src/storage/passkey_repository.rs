use crate::models::passkey::PasskeyItem;
use crate::storage::Database;
use crate::{PersonaError, PersonaResult};
use chrono::{TimeZone, Utc};
use sqlx::Row;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

/// Repository for WebAuthn passkeys (software authenticator credentials).
pub struct PasskeyRepository {
    db: Arc<Database>,
}

impl PasskeyRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    fn item_from_row(row: &sqlx::sqlite::SqliteRow) -> PersonaResult<PasskeyItem> {
        let tags_json: String = row.try_get("tags")?;
        Ok(PasskeyItem {
            id: Uuid::from_str(row.try_get::<String, _>("id")?.as_str())
                .map_err(|e| PersonaError::StorageError(format!("Invalid passkey id: {e}")))?,
            identity_id: Uuid::from_str(row.try_get::<String, _>("identity_id")?.as_str())
                .map_err(|e| PersonaError::StorageError(format!("Invalid identity id: {e}")))?,
            rp_id: row.try_get("rp_id")?,
            rp_name: row.try_get("rp_name")?,
            user_handle: row.try_get("user_handle")?,
            user_name: row.try_get("user_name")?,
            user_display_name: row.try_get("user_display_name")?,
            credential_id: row.try_get("credential_id")?,
            encrypted_private_key: row.try_get("encrypted_private_key")?,
            wrapped_item_key: row.try_get("wrapped_item_key")?,
            public_key_cose: row.try_get("public_key_cose")?,
            alg: row.try_get::<i64, _>("alg")?,
            sign_count: row.try_get::<i64, _>("sign_count")? as u32,
            uv_initialized: row.try_get::<i64, _>("uv_initialized")? != 0,
            export_allowed: row.try_get::<i64, _>("export_allowed")? != 0,
            created_at: Utc
                .timestamp_opt(row.try_get::<i64, _>("created_at")?, 0)
                .single()
                .unwrap_or_default(),
            last_used_at: row
                .try_get::<Option<i64>, _>("last_used_at")?
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        })
    }

    /// Create a new passkey entry
    pub async fn create(&self, item: &PasskeyItem) -> PersonaResult<PasskeyItem> {
        sqlx::query(
            r#"
            INSERT INTO passkeys (
                id, identity_id, rp_id, rp_name, user_handle, user_name,
                user_display_name, credential_id, encrypted_private_key,
                wrapped_item_key, public_key_cose, alg, sign_count,
                uv_initialized, export_allowed, created_at, last_used_at, tags
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            "#,
        )
        .bind(item.id.to_string())
        .bind(item.identity_id.to_string())
        .bind(&item.rp_id)
        .bind(&item.rp_name)
        .bind(&item.user_handle)
        .bind(&item.user_name)
        .bind(&item.user_display_name)
        .bind(&item.credential_id)
        .bind(&item.encrypted_private_key)
        .bind(&item.wrapped_item_key)
        .bind(&item.public_key_cose)
        .bind(item.alg)
        .bind(item.sign_count as i64)
        .bind(item.uv_initialized as i64)
        .bind(item.export_allowed as i64)
        .bind(item.created_at.timestamp())
        .bind(item.last_used_at.map(|t| t.timestamp()))
        .bind(serde_json::to_string(&item.tags)?)
        .execute(self.db.pool())
        .await?;
        Ok(item.clone())
    }

    /// Find a passkey by ID
    pub async fn find_by_id(&self, id: &Uuid) -> PersonaResult<Option<PasskeyItem>> {
        let row = sqlx::query("SELECT * FROM passkeys WHERE id = $1")
            .bind(id.to_string())
            .fetch_optional(self.db.pool())
            .await?;
        row.map(|r| Self::item_from_row(&r)).transpose()
    }

    /// Find a passkey by its WebAuthn credential ID
    pub async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> PersonaResult<Option<PasskeyItem>> {
        let row = sqlx::query("SELECT * FROM passkeys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(self.db.pool())
            .await?;
        row.map(|r| Self::item_from_row(&r)).transpose()
    }

    /// List all passkeys of an identity
    pub async fn find_by_identity(&self, identity_id: &Uuid) -> PersonaResult<Vec<PasskeyItem>> {
        let rows =
            sqlx::query("SELECT * FROM passkeys WHERE identity_id = $1 ORDER BY created_at DESC")
                .bind(identity_id.to_string())
                .fetch_all(self.db.pool())
                .await?;
        rows.iter().map(Self::item_from_row).collect()
    }

    /// List all passkeys for a relying party, across identities
    pub async fn find_by_rp_id(&self, rp_id: &str) -> PersonaResult<Vec<PasskeyItem>> {
        let rows = sqlx::query("SELECT * FROM passkeys WHERE rp_id = $1 ORDER BY created_at DESC")
            .bind(rp_id)
            .fetch_all(self.db.pool())
            .await?;
        rows.iter().map(Self::item_from_row).collect()
    }

    /// Update mutable fields (names, display name, tags, export flag, usage)
    pub async fn update(&self, item: &PasskeyItem) -> PersonaResult<()> {
        let result = sqlx::query(
            r#"
            UPDATE passkeys SET
                rp_name = $2, user_name = $3, user_display_name = $4,
                uv_initialized = $5, export_allowed = $6,
                last_used_at = $7, tags = $8
            WHERE id = $1
            "#,
        )
        .bind(item.id.to_string())
        .bind(&item.rp_name)
        .bind(&item.user_name)
        .bind(&item.user_display_name)
        .bind(item.uv_initialized as i64)
        .bind(item.export_allowed as i64)
        .bind(item.last_used_at.map(|t| t.timestamp()))
        .bind(serde_json::to_string(&item.tags)?)
        .execute(self.db.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(PersonaError::NotFound("Passkey".to_string()));
        }
        Ok(())
    }

    /// Delete a passkey by ID
    pub async fn delete(&self, id: &Uuid) -> PersonaResult<bool> {
        let result = sqlx::query("DELETE FROM passkeys WHERE id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::KeyHierarchy;
    use crate::crypto::passkey::register_passkey;
    use crate::crypto::EncryptionService;

    async fn setup_db() -> Arc<Database> {
        let db = Database::in_memory().await.expect("in-memory database");
        db.migrate().await.expect("migrations");
        Arc::new(db)
    }

    async fn seed_identity(db: &Arc<Database>) -> Uuid {
        let identity_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO identities (
              id, name, identity_type, description, email, phone, ssh_key, gpg_key,
              tags, attributes, created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(identity_id.to_string())
        .bind("Test Identity")
        .bind("personal")
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind("[]")
        .bind("{}")
        .bind(now)
        .bind(now)
        .bind(true)
        .execute(db.pool())
        .await
        .unwrap();
        identity_id
    }

    fn make_item(db: &Arc<Database>, identity_id: Uuid) -> PasskeyItem {
        let client_data = br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
        let reg = register_passkey("example.com", "https://example.com", client_data, false)
            .expect("registration");
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);
        let hierarchy = KeyHierarchy::new(&master);
        let scalar = reg.signing_key.to_bytes();
        let envelope = hierarchy
            .encrypt_with_new_item_key(scalar.as_slice())
            .expect("encrypt");
        let mut item = PasskeyItem::new(
            identity_id,
            "example.com".to_string(),
            b"user-handle".to_vec(),
            reg.credential_id,
            envelope.ciphertext,
            envelope.wrapped_key,
            reg.public_key_cose,
        );
        item.user_name = Some("alice@example.com".to_string());
        let _ = db;
        item
    }

    #[tokio::test]
    async fn create_find_delete_round_trip() {
        let db = setup_db().await;
        let repo = PasskeyRepository::new(db.clone());
        let identity_id = seed_identity(&db).await;
        let item = make_item(&db, identity_id);

        repo.create(&item).await.unwrap();

        let by_id = repo.find_by_id(&item.id).await.unwrap().unwrap();
        assert_eq!(by_id.rp_id, "example.com");
        assert_eq!(by_id.user_name.as_deref(), Some("alice@example.com"));
        assert_eq!(by_id.credential_id, item.credential_id);

        let by_cred = repo
            .find_by_credential_id(&item.credential_id)
            .await
            .unwrap();
        assert_eq!(by_cred.unwrap().id, item.id);

        let by_identity = repo.find_by_identity(&identity_id).await.unwrap();
        assert_eq!(by_identity.len(), 1);

        let by_rp = repo.find_by_rp_id("example.com").await.unwrap();
        assert_eq!(by_rp.len(), 1);

        assert!(repo.delete(&item.id).await.unwrap());
        assert!(repo.find_by_id(&item.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_mutates_listed_fields_only() {
        let db = setup_db().await;
        let repo = PasskeyRepository::new(db.clone());
        let identity_id = seed_identity(&db).await;
        let item = make_item(&db, identity_id);
        repo.create(&item).await.unwrap();

        let mut updated = item.clone();
        updated.user_display_name = Some("Alice".to_string());
        updated.export_allowed = false;
        updated.tags = vec!["work".to_string()];
        updated.last_used_at = Some(chrono::Utc::now());
        repo.update(&updated).await.unwrap();

        let reloaded = repo.find_by_id(&item.id).await.unwrap().unwrap();
        assert_eq!(reloaded.user_display_name.as_deref(), Some("Alice"));
        assert!(!reloaded.export_allowed);
        assert_eq!(reloaded.tags, vec!["work".to_string()]);
        assert!(reloaded.last_used_at.is_some());
        // immutable fields untouched
        assert_eq!(reloaded.encrypted_private_key, item.encrypted_private_key);
        assert_eq!(reloaded.rp_id, item.rp_id);
    }

    #[tokio::test]
    async fn duplicate_credential_id_rejected() {
        let db = setup_db().await;
        let repo = PasskeyRepository::new(db.clone());
        let identity_id = seed_identity(&db).await;
        let item = make_item(&db, identity_id);
        repo.create(&item).await.unwrap();

        let mut second = item.clone();
        second.id = Uuid::new_v4();
        assert!(repo.create(&second).await.is_err());
    }
}
