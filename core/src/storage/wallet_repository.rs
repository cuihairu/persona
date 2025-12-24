use crate::models::wallet::{
    BlockchainNetwork, CryptoWallet, SignedTransaction, TransactionRequest, WalletAddress,
    WalletMetadata, WalletSecurityLevel,
};
use crate::storage::Database;
use crate::{PersonaError, PersonaResult};
use chrono::{DateTime, TimeZone, Utc};
use serde_json;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// Helper to convert Unix timestamp to DateTime<Utc>
#[allow(dead_code)]
fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(ts, 0).unwrap()
}

/// Repository for managing crypto wallets
pub struct CryptoWalletRepository {
    db: Arc<Database>,
}

impl CryptoWalletRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Find all wallets
    pub async fn find_all(&self) -> PersonaResult<Vec<CryptoWallet>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;

            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;

            wallets.push(wallet);
        }

        Ok(wallets)
    }

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

    /// Find wallet by ID
    pub async fn find_by_id(&self, id: &Uuid) -> PersonaResult<Option<CryptoWallet>> {
        let row = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE id = $1
            "#,
        )
        .bind(id.to_string())
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
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE identity_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(identity_id.to_string())
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
    pub async fn find_by_network(
        &self,
        network: &BlockchainNetwork,
    ) -> PersonaResult<Vec<CryptoWallet>> {
        let network_str = serde_json::to_string(network)?;
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE network = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(network_str)
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
    pub async fn find_by_security_level(
        &self,
        security_level: &WalletSecurityLevel,
    ) -> PersonaResult<Vec<CryptoWallet>> {
        let level_str = serde_json::to_string(security_level)?;
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE security_level = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(level_str)
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

    /// Find wallets by name (case-insensitive exact match).
    pub async fn find_by_name(&self, name: &str) -> PersonaResult<Vec<CryptoWallet>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE LOWER(name) = LOWER($1)
            ORDER BY created_at DESC
            "#,
        )
        .bind(name)
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;
            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Find wallets by name substring (case-insensitive).
    pub async fn find_by_name_like(&self, name_pattern: &str) -> PersonaResult<Vec<CryptoWallet>> {
        let like = format!("%{}%", name_pattern.to_lowercase());
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE LOWER(name) LIKE $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(like)
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;
            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Find wallets by ID prefix (useful when CLI shows shortened IDs).
    pub async fn find_by_id_prefix(&self, id_prefix: &str) -> PersonaResult<Vec<CryptoWallet>> {
        let like = format!("{}%", id_prefix);
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, description, network, wallet_type,
                   derivation_path, extended_public_key, encrypted_private_key,
                   encrypted_mnemonic, watch_only, security_level,
                   created_at, updated_at
            FROM crypto_wallets
            WHERE id LIKE $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(like)
        .fetch_all(self.db.pool())
        .await?;

        let mut wallets = Vec::new();
        for row in rows {
            let mut wallet = self.wallet_from_row(&row)?;
            wallet.addresses = self.load_wallet_addresses(&wallet.id).await?;
            wallet.metadata = self.load_wallet_metadata(&wallet.id).await?;
            wallets.push(wallet);
        }

        Ok(wallets)
    }

    /// Update wallet
    pub async fn update(&self, wallet: &CryptoWallet) -> PersonaResult<CryptoWallet> {
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
        .execute(self.db.pool())
        .await?;

        // Delete old addresses and insert new ones
        sqlx::query("DELETE FROM wallet_addresses WHERE wallet_id = $1")
            .bind(wallet.id.to_string())
            .execute(self.db.pool())
            .await?;

        for address in &wallet.addresses {
            self.add_address(&wallet.id, address).await?;
        }

        // Update metadata
        self.update_wallet_metadata(&wallet.id, &wallet.metadata)
            .await?;

        // Return updated wallet
        self.find_by_id(&wallet.id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Failed to find updated wallet".to_string()))
    }

    /// Delete wallet
    pub async fn delete(&self, id: &Uuid) -> PersonaResult<bool> {
        sqlx::query("DELETE FROM wallet_addresses WHERE wallet_id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        sqlx::query("DELETE FROM wallet_metadata WHERE wallet_id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        sqlx::query("DELETE FROM transaction_requests WHERE wallet_id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        sqlx::query("DELETE FROM signed_transactions WHERE wallet_id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        // Delete wallet
        let result = sqlx::query("DELETE FROM crypto_wallets WHERE id = $1")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

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

    /// Create transaction request
    pub async fn create_transaction_request(
        &self,
        request: &TransactionRequest,
    ) -> PersonaResult<TransactionRequest> {
        sqlx::query(
            r#"
            INSERT INTO transaction_requests (
                id, wallet_id, network, from_address, to_address, amount, fee,
                gas_price, gas_limit, nonce, memo, raw_transaction_data,
                required_signatures, created_at, expires_at, metadata, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'pending')
            "#,
        )
        .bind(request.id.to_string())
        .bind(request.wallet_id.to_string())
        .bind(serde_json::to_string(&request.network)?)
        .bind(&request.from_address)
        .bind(&request.to_address)
        .bind(&request.amount)
        .bind(&request.fee)
        .bind(&request.gas_price)
        .bind(request.gas_limit.map(|v| v as i64))
        .bind(request.nonce.map(|v| v as i64))
        .bind(&request.memo)
        .bind(&request.raw_transaction_data)
        .bind(request.required_signatures as i32)
        .bind(request.created_at.timestamp())
        .bind(request.expires_at.map(|d| d.timestamp()))
        .bind(serde_json::to_string(&request.metadata)?)
        .execute(self.db.pool())
        .await?;

        // Return the request as-is since we just inserted it
        Ok(request.clone())
    }

    /// Create signed transaction
    pub async fn create_signed_transaction(
        &self,
        signed_tx: &SignedTransaction,
    ) -> PersonaResult<SignedTransaction> {
        sqlx::query(
            r#"
            INSERT INTO signed_transactions (
                id, wallet_id, request, signatures, raw_signed_transaction,
                transaction_hash, signed_at, broadcast_status, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(signed_tx.id.to_string())
        .bind(signed_tx.request.wallet_id.to_string())
        .bind(serde_json::to_string(&signed_tx.request)?)
        .bind(serde_json::to_string(&signed_tx.signatures)?)
        .bind(&signed_tx.raw_signed_transaction)
        .bind(&signed_tx.transaction_hash)
        .bind(signed_tx.signed_at.timestamp())
        .bind(serde_json::to_string(&signed_tx.broadcast_status)?)
        .bind(chrono::Utc::now().timestamp())
        .execute(self.db.pool())
        .await?;

        Ok(signed_tx.clone())
    }

    /// Get pending transaction requests for a wallet
    pub async fn get_pending_requests(
        &self,
        wallet_id: &Uuid,
    ) -> PersonaResult<Vec<TransactionRequest>> {
        let rows = sqlx::query(
            r#"
            SELECT id, wallet_id, network, from_address, to_address, amount, fee,
                   gas_price, gas_limit, nonce, memo, raw_transaction_data,
                   required_signatures, created_at, signed_at, expires_at, metadata, status
            FROM transaction_requests
            WHERE wallet_id = $1 AND signed_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_all(self.db.pool())
        .await?;

        let mut requests = Vec::new();
        for row in rows {
            requests.push(self.transaction_request_from_row(&row)?);
        }

        Ok(requests)
    }

    /// Get transaction statistics for a wallet
    pub async fn get_transaction_stats(
        &self,
        wallet_id: &Uuid,
    ) -> PersonaResult<WalletTransactionStats> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastSuccess%' THEN 1 END) as successful_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastFailed%' THEN 1 END) as failed_transactions
            FROM signed_transactions
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_one(self.db.pool())
        .await?;

        Ok(WalletTransactionStats {
            total_transactions: row.get::<i64, _>("total_transactions") as u64,
            successful_transactions: row.get::<i64, _>("successful_transactions") as u64,
            failed_transactions: row.get::<i64, _>("failed_transactions") as u64,
            total_amount_sent: 0.0, // Not easily computed without parsing amounts
        })
    }

    // Private helper methods

    fn wallet_from_row(&self, row: &sqlx::sqlite::SqliteRow) -> PersonaResult<CryptoWallet> {
        let id_str: String = row.get("id");
        let identity_id_str: String = row.get("identity_id");
        let network_str: String = row.get("network");
        let wallet_type_str: String = row.get("wallet_type");
        let security_level_str: String = row.get("security_level");
        let created_at_ts: i64 = row.get("created_at");
        let updated_at_ts: i64 = row.get("updated_at");

        Ok(CryptoWallet {
            id: Uuid::parse_str(&id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            identity_id: Uuid::parse_str(&identity_id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            name: row.get("name"),
            description: row.get("description"),
            network: serde_json::from_str(&network_str)?,
            wallet_type: serde_json::from_str(&wallet_type_str)?,
            derivation_path: row.get("derivation_path"),
            extended_public_key: row.get("extended_public_key"),
            encrypted_private_key: row.get("encrypted_private_key"),
            encrypted_mnemonic: row.get("encrypted_mnemonic"),
            addresses: Vec::new(),        // Loaded separately
            metadata: Default::default(), // Loaded separately
            created_at: Utc.timestamp_opt(created_at_ts, 0).unwrap(),
            updated_at: Utc.timestamp_opt(updated_at_ts, 0).unwrap(),
            watch_only: row.get("watch_only"),
            security_level: serde_json::from_str(&security_level_str)?,
        })
    }

    async fn load_wallet_addresses(&self, wallet_id: &Uuid) -> PersonaResult<Vec<WalletAddress>> {
        let rows = sqlx::query(
            r#"
            SELECT id, wallet_id, address, address_type, derivation_path, "index",
                   used, balance, last_activity, metadata, created_at
            FROM wallet_addresses
            WHERE wallet_id = $1
            ORDER BY "index" ASC
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_all(self.db.pool())
        .await?;

        let mut addresses = Vec::new();
        for row in rows {
            let address_type_str: String = row.get("address_type");
            let metadata_str: String = row.get("metadata");
            let created_at_ts: i64 = row.get("created_at");
            let last_activity_ts: Option<i64> = row.get("last_activity");

            addresses.push(WalletAddress {
                address: row.get("address"),
                address_type: serde_json::from_str(&address_type_str)?,
                derivation_path: row.get("derivation_path"),
                index: row.get::<i64, _>("index") as u32,
                used: row.get("used"),
                balance: row.get("balance"),
                last_activity: last_activity_ts.map(|ts| Utc.timestamp_opt(ts, 0).unwrap()),
                metadata: serde_json::from_str(&metadata_str)?,
                created_at: Utc.timestamp_opt(created_at_ts, 0).unwrap(),
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

    async fn insert_address(
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

    async fn load_wallet_metadata(&self, wallet_id: &Uuid) -> PersonaResult<WalletMetadata> {
        let row = sqlx::query(
            r#"
            SELECT tags, notes, platform, purpose,
                   associated_services, backup_info, security_settings, custom_data
            FROM wallet_metadata
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_optional(self.db.pool())
        .await?;

        match row {
            Some(row) => {
                let tags_str: String = row.get("tags");
                let associated_services_str: String = row.get("associated_services");
                let backup_info_str: Option<String> = row.get("backup_info");
                let security_settings_str: String = row.get("security_settings");
                let custom_data_str: String = row.get("custom_data");

                Ok(WalletMetadata {
                    tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                    notes: row.get("notes"),
                    platform: row.get("platform"),
                    purpose: row.get("purpose"),
                    associated_services: serde_json::from_str(&associated_services_str).unwrap_or_default(),
                    backup_info: backup_info_str.and_then(|s| serde_json::from_str(&s).ok()),
                    security_settings: serde_json::from_str(&security_settings_str).unwrap_or_default(),
                    custom_data: serde_json::from_str(&custom_data_str).unwrap_or_default(),
                })
            }
            None => Ok(Default::default()),
        }
    }

    async fn update_wallet_metadata(
        &self,
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
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    fn transaction_request_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
    ) -> PersonaResult<TransactionRequest> {
        let id_str: String = row.get("id");
        let wallet_id_str: String = row.get("wallet_id");
        let network_str: String = row.get("network");
        let metadata_str: String = row.get("metadata");
        let created_at_ts: i64 = row.get("created_at");
        let expires_at_ts: Option<i64> = row.get("expires_at");

        Ok(TransactionRequest {
            id: Uuid::parse_str(&id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            wallet_id: Uuid::parse_str(&wallet_id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            network: serde_json::from_str(&network_str)?,
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
            created_at: Utc.timestamp_opt(created_at_ts, 0).unwrap(),
            expires_at: expires_at_ts.map(|ts| Utc.timestamp_opt(ts, 0).unwrap()),
            metadata: serde_json::from_str(&metadata_str)?,
        })
    }

    #[allow(dead_code)]
    fn signed_transaction_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
    ) -> PersonaResult<SignedTransaction> {
        let id_str: String = row.get("id");
        let request_str: String = row.get("request");
        let signatures_str: String = row.get("signatures");
        let broadcast_status_str: String = row.get("broadcast_status");
        let signed_at_ts: i64 = row.get("signed_at");

        Ok(SignedTransaction {
            id: Uuid::parse_str(&id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            request: serde_json::from_str(&request_str)?,
            signatures: serde_json::from_str(&signatures_str)?,
            raw_signed_transaction: row.get("raw_signed_transaction"),
            transaction_hash: row.get("transaction_hash"),
            signed_at: Utc.timestamp_opt(signed_at_ts, 0).unwrap(),
            broadcast_status: serde_json::from_str(&broadcast_status_str)?,
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
    use crate::models::wallet::{AddressType, WalletAddress, WalletType};
    use crate::storage::Database;

    async fn seed_identity(db: &Database) -> Uuid {
        let identity_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();

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
        .bind(&now)
        .bind(&now)
        .bind(true)
        .execute(db.pool())
        .await
        .unwrap();

        identity_id
    }

    #[tokio::test]
    async fn test_wallet_crud() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let identity_id = seed_identity(&db).await;
        let repo = CryptoWalletRepository::new(Arc::new(db));

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
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let identity_id = seed_identity(&db).await;
        let repo = CryptoWalletRepository::new(Arc::new(db));

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
        let updated = repo
            .update_address_usage(&created.id, &address.address, true)
            .await
            .unwrap();
        assert!(updated);
    }
}
