//! 钱包写入域（LAY-022 拆分）：touch/create/update/delete 与元数据落库 helper。

use super::*;

impl CryptoWalletRepository {
    /// Update the wallet `updated_at` timestamp to now.
    pub async fn touch(&self, wallet_id: &Uuid) -> PersonaResult<()> {
        sqlx::query("UPDATE crypto_wallets SET updated_at = $2 WHERE id = $1")
            .bind(wallet_id.to_string())
            .bind(chrono::Utc::now().timestamp())
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Create a new crypto wallet
    pub async fn create(&self, wallet: &CryptoWallet) -> PersonaResult<CryptoWallet> {
        let mut tx = self.db.pool().begin().await?;

        // Insert wallet
        sqlx::query(
            r#"
            INSERT INTO crypto_wallets (
                id, identity_id, name, description, network, wallet_type,
                derivation_path, extended_public_key, encrypted_private_key,
                encrypted_mnemonic, watch_only, security_level,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(wallet.id.to_string())
        .bind(wallet.identity_id.to_string())
        .bind(&wallet.name)
        .bind(&wallet.description)
        .bind(serde_json::to_string(&wallet.network)?)
        .bind(serde_json::to_string(&wallet.wallet_type)?)
        .bind(&wallet.derivation_path)
        .bind(&wallet.extended_public_key)
        .bind(&wallet.encrypted_private_key)
        .bind(&wallet.encrypted_mnemonic)
        .bind(wallet.watch_only)
        .bind(serde_json::to_string(&wallet.security_level)?)
        .bind(wallet.created_at.timestamp())
        .bind(wallet.updated_at.timestamp())
        .execute(tx.as_mut())
        .await?;

        // Insert metadata
        self.insert_wallet_metadata(&mut tx, &wallet.id, &wallet.metadata)
            .await?;

        // Insert addresses
        for address in &wallet.addresses {
            self.insert_address(&mut tx, &wallet.id, address).await?;
        }

        tx.commit().await?;

        // Load and return the created wallet
        self.find_by_id(&wallet.id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Wallet".to_string()))
    }

    /// Update wallet
    ///
    /// 全程同一事务（2026-11-13 codex 深审 Critical 修复）：钱包行更新、
    /// 地址重建与元数据更新此前各自独立提交，中途约束失败会留下新密钥、
    /// 残缺地址与旧元数据的混合状态；现在任一步失败整体回滚。
    pub async fn update(&self, wallet: &CryptoWallet) -> PersonaResult<CryptoWallet> {
        let mut tx = self.db.pool().begin().await?;

        sqlx::query(
            r#"
            UPDATE crypto_wallets SET
                name = $2, description = $3, network = $4, wallet_type = $5,
                derivation_path = $6, extended_public_key = $7, encrypted_private_key = $8,
                encrypted_mnemonic = $9, watch_only = $10, security_level = $11,
                updated_at = $12
            WHERE id = $1
            "#,
        )
        .bind(wallet.id.to_string())
        .bind(&wallet.name)
        .bind(&wallet.description)
        .bind(serde_json::to_string(&wallet.network)?)
        .bind(serde_json::to_string(&wallet.wallet_type)?)
        .bind(&wallet.derivation_path)
        .bind(&wallet.extended_public_key)
        .bind(&wallet.encrypted_private_key)
        .bind(&wallet.encrypted_mnemonic)
        .bind(wallet.watch_only)
        .bind(serde_json::to_string(&wallet.security_level)?)
        .bind(wallet.updated_at.timestamp())
        .execute(tx.as_mut())
        .await?;

        // Delete old addresses and insert new ones
        sqlx::query("DELETE FROM wallet_addresses WHERE wallet_id = $1")
            .bind(wallet.id.to_string())
            .execute(tx.as_mut())
            .await?;

        for address in &wallet.addresses {
            self.insert_address(&mut tx, &wallet.id, address).await?;
        }

        // Update metadata
        self.update_wallet_metadata(&mut tx, &wallet.id, &wallet.metadata)
            .await?;

        tx.commit().await?;

        // Return updated wallet
        self.find_by_id(&wallet.id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Failed to find updated wallet".to_string()))
    }

    /// Delete wallet
    ///
    /// 单条父表删除（2026-11-13 codex 深审 Critical 修复）：四张子表
    /// （wallet_addresses/wallet_metadata/transaction_requests/signed_transactions，
    /// 见 migrations/009_crypto_wallets.sql）均带 `ON DELETE CASCADE` 且
    /// 连接层启用外键强制，级联在 SQLite 同一条语句内完成，天然原子——
    /// 此前逐表独立删除在中间失败时会留下半删除状态。
    pub async fn delete(&self, id: &Uuid) -> PersonaResult<bool> {
        let result = sqlx::query("DELETE FROM crypto_wallets WHERE id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn insert_wallet_metadata(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wallet_id: &Uuid,
        metadata: &WalletMetadata,
    ) -> PersonaResult<()> {
        // Insert metadata as JSON in a separate table for better queryability
        sqlx::query(
            r#"
            INSERT INTO wallet_metadata (
                wallet_id, tags, notes, platform, purpose,
                associated_services, backup_info, security_settings, custom_data,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(wallet_id.to_string())
        .bind(serde_json::to_string(&metadata.tags)?)
        .bind(&metadata.notes)
        .bind(&metadata.platform)
        .bind(&metadata.purpose)
        .bind(serde_json::to_string(&metadata.associated_services)?)
        .bind(serde_json::to_string(&metadata.backup_info)?)
        .bind(serde_json::to_string(&metadata.security_settings)?)
        .bind(serde_json::to_string(&metadata.custom_data)?)
        .bind(chrono::Utc::now().timestamp())
        .bind(chrono::Utc::now().timestamp())
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    async fn update_wallet_metadata(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wallet_id: &Uuid,
        metadata: &WalletMetadata,
    ) -> PersonaResult<()> {
        sqlx::query(
            r#"
            UPDATE wallet_metadata SET
                tags = $2, notes = $3, platform = $4, purpose = $5,
                associated_services = $6, backup_info = $7,
                security_settings = $8, custom_data = $9,
                updated_at = $10
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet_id.to_string())
        .bind(serde_json::to_string(&metadata.tags)?)
        .bind(&metadata.notes)
        .bind(&metadata.platform)
        .bind(&metadata.purpose)
        .bind(serde_json::to_string(&metadata.associated_services)?)
        .bind(serde_json::to_string(&metadata.backup_info)?)
        .bind(serde_json::to_string(&metadata.security_settings)?)
        .bind(serde_json::to_string(&metadata.custom_data)?)
        .bind(chrono::Utc::now().timestamp())
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }
}
