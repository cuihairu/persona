use crate::models::wallet::{
    CryptoWallet, WalletAddress, TransactionRequest, SignedTransaction,
    BlockchainNetwork, WalletSecurityLevel, WalletMetadata,
};
use crate::storage::Database;
use crate::{PersonaResult, PersonaError};
use serde_json;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// Repository for managing crypto wallets
pub struct CryptoWalletRepository {
    db: Arc<Database>,
}

impl CryptoWalletRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Create a new crypto wallet
    pub async fn create(&self, wallet: &CryptoWallet) -> PersonaResult<CryptoWallet> {
        let mut tx = self.db.pool().begin().await?;

        // Insert wallet
        sqlx::query!(
            r#"
            INSERT INTO crypto_wallets (
                id, identity_id, name, description, network, wallet_type,
                derivation_path, extended_public_key, encrypted_private_key,
                encrypted_mnemonic, watch_only, security_level,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            wallet.id,
            wallet.identity_id,
            wallet.name,
            wallet.description,
            serde_json::to_string(&wallet.network)?,
            serde_json::to_string(&wallet.wallet_type)?,
            wallet.derivation_path,
            wallet.extended_public_key,
            wallet.encrypted_private_key,
            wallet.encrypted_mnemonic,
            wallet.watch_only,
            serde_json::to_string(&wallet.security_level)?,
            wallet.created_at,
            wallet.updated_at,
        )
        .execute(tx.as_mut())
        .await?;

        // Insert metadata
        self.insert_wallet_metadata(tx, &wallet.id, &wallet.metadata).await?;

        // Insert addresses
        for address in &wallet.addresses {
            self.insert_address(tx, &wallet.id, address).await?;
        }

        tx.commit().await?;

        // Load and return the created wallet
        self.find_by_id(&wallet.id).await?
            .ok_or_else(|| PersonaError::NotFound("Wallet".to_string()))
    }

    /// Find wallet by ID
    pub async fn find_by_id(&self, id: &Uuid) -> PersonaResult<Option<CryptoWallet>> {
        let row = sqlx::query!(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(self.db.pool())
        .await?;

        match row {
            Some(row) => {
                let mut wallet = self.wallet_from_row(&row)?;

                // Load addresses
                wallet.addresses = self.load_wallet_addresses(id).await?;

                // Load metadata
                wallet.metadata = self.load_wallet_metadata(id).await?;

                Ok(Some(wallet))
            }
            None => Ok(None),
        }
    }

    /// Find all wallets for an identity
    pub async fn find_by_identity(&self, identity_id: &Uuid) -> PersonaResult<Vec<CryptoWallet>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE identity_id = $1
            ORDER BY created_at DESC
            "#,
            identity_id,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;

            // Load addresses
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;

            // Load metadata
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;

            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Find wallets by network
    pub async fn find_by_network(&self, network: &BlockchainNetwork) -> PersonaResult<Vec<CryptoWallet>> {
        let network_str = serde_json::to_string(network)?;
        let rows = sqlx::query!(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE network = $1
            ORDER BY created_at DESC
            "#,
            network_str,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;

            // Load addresses
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;

            // Load metadata
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;

            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Find wallets by security level
    pub async fn find_by_security_level(&self, security_level: &WalletSecurityLevel) -> PersonaResult<Vec<CryptoWallet>> {
        let level_str = serde_json::to_string(security_level)?;
        let rows = sqlx::query!(
            r#"
            SELECT * FROM crypto_wallets WHERE security_level = $1 ORDER BY created_at DESC
            "#,
            level_str,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;

            // Load addresses
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;

            // Load metadata
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;

            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Update wallet
    pub async fn update(&self, wallet: &CryptoWallet) -> PersonaResult<CryptoWallet> {
        sqlx::query!(
            r#"
            UPDATE crypto_wallets SET
                name = $2, description = $3, network = $4, wallet_type = $5,
                derivation_path = $6, extended_public_key = $7, encrypted_private_key = $8,
                encrypted_mnemonic = $9, watch_only = $10, security_level = $11,
                updated_at = $12
            WHERE id = $1
            "#,
            wallet.id,
            wallet.name,
            wallet.description,
            serde_json::to_string(&wallet.network)?,
            serde_json::to_string(&wallet.wallet_type)?,
            wallet.derivation_path,
            wallet.extended_public_key,
            wallet.encrypted_private_key,
            wallet.encrypted_mnemonic,
            wallet.watch_only,
            serde_json::to_string(&wallet.security_level)?,
            wallet.updated_at,
        )
        .execute(self.db.pool())
        .await?;

        // Delete old addresses and insert new ones
        sqlx::query!("DELETE FROM wallet_addresses WHERE wallet_id = $1", wallet.id)
            .execute(self.db.pool())
            .await?;

        for address in &wallet.addresses {
            self.add_address(&wallet.id, address).await?;
        }

        // Update metadata
        self.update_wallet_metadata(&wallet.id, &wallet.metadata).await?;

        // Return updated wallet
        self.find_by_id(&wallet.id).await?.ok_or_else(|| PersonaError::NotFound("Failed to find updated wallet".to_string()))
    }

    /// Delete wallet
    pub async fn delete(&self, id: &Uuid) -> PersonaResult<bool> {
        sqlx::query!("DELETE FROM wallet_addresses WHERE wallet_id = $1", id)
            .execute(self.db.pool())
            .await?;

        sqlx::query!("DELETE FROM wallet_metadata WHERE wallet_id = $1", id)
            .execute(self.db.pool())
            .await?;

        sqlx::query!("DELETE FROM transaction_requests WHERE wallet_id = $1", id)
            .execute(self.db.pool())
            .await?;

        sqlx::query!("DELETE FROM signed_transactions WHERE wallet_id = $1", id)
            .execute(self.db.pool())
            .await?;

        // Delete wallet
        let result = sqlx::query!("DELETE FROM crypto_wallets WHERE id = $1", id)
            .execute(self.db.pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Add address to wallet
    pub async fn add_address(&self, wallet_id: &Uuid, address: &WalletAddress) -> PersonaResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO wallet_addresses (
                id, wallet_id, address, address_type, derivation_path, index,
                used, balance, last_activity, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            Uuid::new_v4(),
            wallet_id,
            address.address,
            serde_json::to_string(&address.address_type)?,
            address.derivation_path,
            address.index as i64,
            address.used,
            address.balance,
            address.last_activity,
            serde_json::to_value(&address.metadata)?,
            address.created_at,
        )
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Update address usage
    pub async fn update_address_usage(&self, wallet_id: &Uuid, address: &str, used: bool) -> PersonaResult<bool> {
        let result = sqlx::query!(
            r#"
            UPDATE wallet_addresses SET
                used = $2,
                last_activity = $3
            WHERE wallet_id = $1 AND address = $4
            "#,
            wallet_id,
            used,
            chrono::Utc::now(),
            address,
        )
        .execute(self.db.pool())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Create transaction request
    pub async fn create_transaction_request(&self, request: &TransactionRequest) -> PersonaResult<TransactionRequest> {
        let row = sqlx::query!(
            r#"
            INSERT INTO transaction_requests (
                id, wallet_id, network, from_address, to_address, amount, fee,
                gas_price, gas_limit, nonce, memo, raw_transaction_data,
                required_signatures, created_at, expires_at, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            "#,
            request.id,
            request.wallet_id,
            serde_json::to_string(&request.network)?,
            request.from_address,
            request.to_address,
            request.amount,
            request.fee,
            request.gas_price,
            request.gas_limit.map(|v| v as i64),
            request.nonce.map(|v| v as i64),
            request.memo,
            request.raw_transaction_data,
            request.required_signatures as i32,
            request.created_at,
            request.expires_at,
            serde_json::to_value(&request.metadata)?,
        )
        .fetch_one(self.db.pool())
        .await?;

        self.transaction_request_from_row(&row).await
    }

    /// Create signed transaction
    pub async fn create_signed_transaction(&self, signed_tx: &SignedTransaction) -> PersonaResult<SignedTransaction> {
        let row = sqlx::query!(
            r#"
            INSERT INTO signed_transactions (
                id, request, signatures, raw_signed_transaction,
                transaction_hash, signed_at, broadcast_status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            signed_tx.id,
            serde_json::to_string(&signed_tx.request)?,
            serde_json::to_string(&signed_tx.signatures)?,
            signed_tx.raw_signed_transaction,
            signed_tx.transaction_hash,
            signed_tx.signed_at,
            serde_json::to_string(&signed_tx.broadcast_status)?,
        )
        .fetch_one(self.db.pool())
        .await?;

        self.signed_transaction_from_row(&row).await
    }

    /// Get pending transaction requests for a wallet
    pub async fn get_pending_requests(&self, wallet_id: &Uuid) -> PersonaResult<Vec<TransactionRequest>> {
        let rows = sqlx::query!(
            r#"
            SELECT * FROM transaction_requests
            WHERE wallet_id = $1 AND (
                signed_at IS NULL
                OR (expires_at IS NOT NULL AND expires_at > NOW())
            )
            ORDER BY created_at DESC
            "#,
            wallet_id,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut requests = Vec::new();
        for row in rows {
            requests.push(self.transaction_request_from_row(&row)?);
        }

        Ok(requests)
    }

    /// Get transaction statistics for a wallet
    pub async fn get_transaction_stats(&self, wallet_id: &Uuid) -> PersonaResult<WalletTransactionStats> {
        let stats = sqlx::query!(
            r#"
            SELECT
                COUNT(*) as total_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastSuccess%' THEN 1 END) as successful_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastFailed%' THEN 1 END) as failed_transactions,
                SUM(CASE WHEN amount IS NOT NULL THEN CAST(amount AS NUMERIC) ELSE 0 END) as total_amount_sent
            FROM signed_transactions
            WHERE wallet_id = $1
            "#,
            wallet_id,
        )
        .fetch_one(self.db.pool())
        .await?;

        Ok(WalletTransactionStats {
            total_transactions: stats.total_transactions.unwrap_or(0) as u64,
            successful_transactions: stats.successful_transactions.unwrap_or(0) as u64,
            failed_transactions: stats.failed_transactions.unwrap_or(0) as u64,
            total_amount_sent: stats.total_amount_sent.unwrap_or(0.0),
        })
    }

    // Private helper methods

    fn wallet_from_row(&self, row: &sqlx::sqlite::SqliteRow) -> PersonaResult<CryptoWallet> {
        Ok(CryptoWallet {
            id: row.get("id"),
            identity_id: row.get("identity_id"),
            name: row.get("name"),
            description: row.get("description"),
            network: serde_json::from_str(row.get("network"))?,
            wallet_type: serde_json::from_str(row.get("wallet_type"))?,
            derivation_path: row.get("derivation_path"),
            extended_public_key: row.get("extended_public_key"),
            encrypted_private_key: row.get("encrypted_private_key"),
            encrypted_mnemonic: row.get("encrypted_mnemonic"),
            addresses: Vec::new(), // Loaded separately
            metadata: Default::default(), // Loaded separately
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            watch_only: row.get("watch_only"),
            security_level: serde_json::from_str(row.get("security_level"))?,
        })
    }

    async fn load_wallet_addresses(&self, wallet_id: &Uuid) -> PersonaResult<Vec<WalletAddress>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, wallet_id, address, address_type, derivation_path, index,
                   used, balance, last_activity, metadata, created_at
            FROM wallet_addresses
            WHERE wallet_id = $1
            ORDER BY index ASC
            "#,
            wallet_id,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut addresses = Vec::new();
        for row in rows {
            addresses.push(WalletAddress {
                address: row.get("address"),
                address_type: serde_json::from_str(row.get("address_type"))?,
                derivation_path: row.get("derivation_path"),
                index: row.get::<i64, _>("index") as u32,
                used: row.get("used"),
                balance: row.get("balance"),
                last_activity: row.get("last_activity"),
                metadata: serde_json::from_value(row.get("metadata"))?,
                created_at: row.get("created_at"),
            });
        }

        Ok(addresses)
    }

    async fn insert_wallet_metadata(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wallet_id: &Uuid,
        metadata: &WalletMetadata,
    ) -> PersonaResult<()> {
        // Insert metadata as JSON in a separate table for better queryability
        sqlx::query!(
            r#"
            INSERT INTO wallet_metadata (
                wallet_id, tags, notes, platform, purpose,
                associated_services, backup_info, security_settings, custom_data,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            wallet_id.to_string(),
            serde_json::to_string(&metadata.tags)?,
            metadata.notes,
            metadata.platform,
            metadata.purpose,
            serde_json::to_string(&metadata.associated_services)?,
            serde_json::to_value(&metadata.backup_info)?,
            serde_json::to_string(&metadata.security_settings)?,
            serde_json::to_string(&metadata.custom_data)?,
            chrono::Utc::now().timestamp(),
            chrono::Utc::now().timestamp(),
        )
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    async fn insert_address(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wallet_id: &Uuid,
        address: &WalletAddress,
    ) -> PersonaResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO wallet_addresses (
                id, wallet_id, address, address_type, derivation_path, index,
                used, balance, last_activity, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            Uuid::new_v4().to_string(),
            wallet_id.to_string(),
            address.address,
            serde_json::to_string(&address.address_type)?,
            address.derivation_path,
            address.index as i64,
            address.used,
            address.balance,
            address.last_activity.map(|d| d.timestamp()),
            serde_json::to_string(&address.metadata)?,
            address.created_at.timestamp(),
        )
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    async fn load_wallet_metadata(&self, wallet_id: &Uuid) -> PersonaResult<WalletMetadata> {
        let row = sqlx::query!(
            r#"
            SELECT tags, notes, platform, purpose,
                   associated_services, backup_info, security_settings, custom_data
            FROM wallet_metadata
            WHERE wallet_id = $1
            "#,
            wallet_id,
        )
        .fetch_optional(self.db.pool())
        .await?;

        match row {
            Some(row) => Ok(WalletMetadata {
                tags: serde_json::from_value(row.tags.unwrap_or_else(|| serde_json::json!([])))?,
                notes: row.notes,
                platform: row.platform,
                purpose: row.purpose,
                associated_services: serde_json::from_value(row.associated_services.unwrap_or_else(|| serde_json::json!([])))?,
                backup_info: row.backup_info.and_then(|v| serde_json::from_value(v).ok()),
                security_settings: serde_json::from_value(row.security_settings.unwrap_or_else(|| serde_json::json!({})))?,
                custom_data: serde_json::from_value(row.custom_data.unwrap_or_else(|| serde_json::json!({})))?,
            }),
            None => Ok(Default::default()),
        }
    }

    async fn update_wallet_metadata(
        &self,
        wallet_id: &Uuid,
        metadata: &WalletMetadata,
    ) -> PersonaResult<()> {
        sqlx::query!(
            r#"
            UPDATE wallet_metadata SET
                tags = $2, notes = $3, platform = $4, purpose = $5,
                associated_services = $6, backup_info = $7,
                security_settings = $8, custom_data = $9,
                updated_at = $10
            WHERE wallet_id = $1
            "#,
            wallet_id,
            serde_json::to_value(&metadata.tags)?,
            metadata.notes,
            metadata.platform,
            metadata.purpose,
            serde_json::to_value(&metadata.associated_services)?,
            serde_json::to_value(&metadata.backup_info)?,
            serde_json::to_value(&metadata.security_settings)?,
            serde_json::to_value(&metadata.custom_data)?,
            chrono::Utc::now(),
        )
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    fn transaction_request_from_row(&self, row: &sqlx::sqlite::SqliteRow) -> PersonaResult<TransactionRequest> {
        Ok(TransactionRequest {
            id: row.get("id"),
            wallet_id: row.get("wallet_id"),
            network: serde_json::from_str(row.get("network"))?,
            from_address: row.get("from_address"),
            to_address: row.get("to_address"),
            amount: row.get("amount"),
            fee: row.get("fee"),
            gas_price: row.get("gas_price"),
            gas_limit: row.get::<Option<i64>, _>("gas_limit").map(|v| v as u64),
            nonce: row.get::<Option<i64>, _>("nonce").map(|v| v as u64),
            memo: row.get("memo"),
            raw_transaction_data: row.get("raw_transaction_data"),
            required_signatures: row.get::<i32, _>("required_signatures") as usize,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            metadata: serde_json::from_value(row.get("metadata"))?,
        })
    }

    fn signed_transaction_from_row(&self, row: &sqlx::sqlite::SqliteRow) -> PersonaResult<SignedTransaction> {
        Ok(SignedTransaction {
            id: row.get("id"),
            request: serde_json::from_str(row.get("request"))?,
            signatures: serde_json::from_str(row.get("signatures"))?,
            raw_signed_transaction: row.get("raw_signed_transaction"),
            transaction_hash: row.get("transaction_hash"),
            signed_at: row.get("signed_at"),
            broadcast_status: serde_json::from_str(row.get("broadcast_status"))?,
        })
    }
}

/// Wallet transaction statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletTransactionStats {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub total_amount_sent: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::wallet::{WalletType, WalletAddress, AddressType};
    use crate::storage::Database;

    #[tokio::test]
    async fn test_wallet_crud() {
        let db = Database::in_memory().await;
        let repo = CryptoWalletRepository::new(Arc::new(db));
        let identity_id = Uuid::new_v4();

        let wallet = CryptoWallet::new(
            identity_id,
            "Test Wallet".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        // Create
        let created = repo.create(&wallet).await.unwrap();
        assert_eq!(created.name, "Test Wallet");
        assert_eq!(created.identity_id, identity_id);

        // Find by ID
        let found = repo.find_by_id(&created.id).await.unwrap().unwrap();
        assert_eq!(found.name, created.name);

        // Find by identity
        let by_identity = repo.find_by_identity(&identity_id).await.unwrap();
        assert_eq!(by_identity.len(), 1);

        // Update
        let mut updated_wallet = found.clone();
        updated_wallet.name = "Updated Wallet".to_string();
        updated_wallet.updated_at = chrono::Utc::now();
        let updated = repo.update(&updated_wallet).await.unwrap();
        assert_eq!(updated.name, "Updated Wallet");

        // Delete
        let deleted = repo.delete(&updated.id).await.unwrap();
        assert!(deleted);

        // Verify deletion
        let found_deleted = repo.find_by_id(&updated.id).await.unwrap();
        assert!(found_deleted.is_none());
    }

    #[tokio::test]
    async fn test_address_management() {
        let db = Database::in_memory().await;
        let repo = CryptoWalletRepository::new(Arc::new(db));
        let identity_id = Uuid::new_v4();

        let mut wallet = CryptoWallet::new(
            identity_id,
            "Test Wallet".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        let address = WalletAddress {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            address_type: AddressType::P2PKH,
            derivation_path: None,
            index: 0,
            used: false,
            balance: None,
            last_activity: None,
            metadata: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
        };

        wallet.add_address(address.clone());

        // Create wallet with address
        let created = repo.create(&wallet).await.unwrap();
        assert_eq!(created.addresses.len(), 1);
        assert_eq!(created.addresses[0].address, address.address);

        // Update address usage
        let updated = repo.update_address_usage(&created.id, &address.address, true).await.unwrap();
        assert!(updated);
    }
}