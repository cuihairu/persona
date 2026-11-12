//! wallet_repository 拆分（LAY-022）测试枢纽：跨域共享 fixture/helper + 按域分组。
//! 各分组经 `use super::*` 级联（枢纽导入与 helper 对后代可见）。

use super::*;
use crate::models::wallet::{AddressType, WalletAddress, WalletType};
use crate::storage::Database;

mod crud;
mod robustness;
mod tx;

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

fn make_wallet(identity_id: Uuid, name: &str) -> CryptoWallet {
    CryptoWallet::new(
        identity_id,
        name.to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    )
}

fn make_address(addr: &str, index: u32) -> WalletAddress {
    WalletAddress {
        address: addr.to_string(),
        address_type: AddressType::P2PKH,
        derivation_path: Some("m/44'/0'/0'/0/0".to_string()),
        index,
        used: false,
        balance: Some("1000".to_string()),
        last_activity: Some(chrono::Utc::now()),
        metadata: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    }
}
