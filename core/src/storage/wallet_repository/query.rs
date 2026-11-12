//! 钱包查询域（LAY-022 拆分）：全量/按身份/网络/安全级别/名称/前缀查询，
//! 及查询共用的行→模型映射 helper。

use super::*;

impl CryptoWalletRepository {
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
            identity_id: Uuid::parse_str(&identity_id_str)
                .map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
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
            created_at: timestamp_to_datetime(created_at_ts)?,
            updated_at: timestamp_to_datetime(updated_at_ts)?,
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
                last_activity: last_activity_ts.map(timestamp_to_datetime).transpose()?,
                metadata: serde_json::from_str(&metadata_str)?,
                created_at: timestamp_to_datetime(created_at_ts)?,
            });
        }

        Ok(addresses)
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
                    associated_services: serde_json::from_str(&associated_services_str)
                        .unwrap_or_default(),
                    backup_info: backup_info_str.and_then(|s| serde_json::from_str(&s).ok()),
                    security_settings: serde_json::from_str(&security_settings_str)
                        .unwrap_or_default(),
                    custom_data: serde_json::from_str(&custom_data_str).unwrap_or_default(),
                })
            }
            None => Ok(Default::default()),
        }
    }
}
