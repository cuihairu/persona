//! 地址维护域（LAY-022 拆分）：add_address / update_address_usage 与地址落库 helper。

use super::*;

impl CryptoWalletRepository {
    /// Add address to wallet
    pub async fn add_address(
        &self,
        wallet_id: &Uuid,
        address: &WalletAddress,
    ) -> PersonaResult<()> {
        sqlx::query(
            r#"
            INSERT INTO wallet_addresses (
                id, wallet_id, address, address_type, derivation_path, "index",
                used, balance, last_activity, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(wallet_id.to_string())
        .bind(&address.address)
        .bind(serde_json::to_string(&address.address_type)?)
        .bind(&address.derivation_path)
        .bind(address.index as i64)
        .bind(address.used)
        .bind(&address.balance)
        .bind(address.last_activity.map(|d| d.timestamp()))
        .bind(serde_json::to_string(&address.metadata)?)
        .bind(address.created_at.timestamp())
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Update address usage
    pub async fn update_address_usage(
        &self,
        wallet_id: &Uuid,
        address: &str,
        used: bool,
    ) -> PersonaResult<bool> {
        let result = sqlx::query(
            r#"
            UPDATE wallet_addresses SET
                used = $2,
                last_activity = $3
            WHERE wallet_id = $1 AND address = $4
            "#,
        )
        .bind(wallet_id.to_string())
        .bind(used)
        .bind(chrono::Utc::now().timestamp())
        .bind(address)
        .execute(self.db.pool())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub(super) async fn insert_address(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wallet_id: &Uuid,
        address: &WalletAddress,
    ) -> PersonaResult<()> {
        sqlx::query(
            r#"
            INSERT INTO wallet_addresses (
                id, wallet_id, address, address_type, derivation_path, "index",
                used, balance, last_activity, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(wallet_id.to_string())
        .bind(&address.address)
        .bind(serde_json::to_string(&address.address_type)?)
        .bind(&address.derivation_path)
        .bind(address.index as i64)
        .bind(address.used)
        .bind(&address.balance)
        .bind(address.last_activity.map(|d| d.timestamp()))
        .bind(serde_json::to_string(&address.metadata)?)
        .bind(address.created_at.timestamp())
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }
}
