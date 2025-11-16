# Persona Core Library Examples

这些示例展示了如何使用 Persona 核心库来管理数字身份和凭据。

## 基础用法

### 1. 初始化服务

```rust
use persona_core::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 创建数据库连接
    let db = Database::from_file("persona.db").await?;
    db.migrate().await?;

    // 创建服务实例
    let mut service = PersonaService::new(db).await?;

    // 生成盐值用于主密钥推导
    let salt = service.generate_salt();

    // 使用主密码解锁服务
    service.unlock("your_master_password", &salt)?;

    Ok(())
}
```

### 2. 创建身份

```rust
// 创建个人身份
let personal_identity = service.create_identity(
    "John Doe".to_string(),
    IdentityType::Personal,
).await?;

// 创建工作身份
let work_identity = service.create_identity(
    "John Doe (Work)".to_string(),
    IdentityType::Work,
).await?;

// 添加标签和属性
let mut identity = personal_identity;
identity.add_tag("primary".to_string());
identity.set_attribute("theme".to_string(), "dark".to_string());
let updated = service.update_identity(&identity).await?;
```

### 3. 管理密码凭据

```rust
// 创建密码凭据数据
let password_data = CredentialData::Password(PasswordCredentialData {
    password: "secure_password_123".to_string(),
    email: Some("john@example.com".to_string()),
    security_questions: vec![
        SecurityQuestion {
            question: "What's your pet's name?".to_string(),
            answer: "Fluffy".to_string(),
        }
    ],
});

// 存储加密的密码凭据
let credential = service.create_credential(
    personal_identity.id,
    "Email Account".to_string(),
    CredentialType::Password,
    SecurityLevel::High,
    &password_data,
).await?;

// 检索和解密凭据
let decrypted_data = service.get_credential_data(&credential.id).await?;
if let Some(CredentialData::Password(pwd_data)) = decrypted_data {
    println!("Password: {}", pwd_data.password);
    println!("Email: {:?}", pwd_data.email);
}
```

### 4. 管理加密货币钱包

```rust
// 创建钱包凭据
let wallet_data = CredentialData::CryptoWallet(CryptoWalletData {
    wallet_type: "Bitcoin".to_string(),
    mnemonic_phrase: Some("abandon abandon abandon...".to_string()),
    private_key: Some("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ".to_string()),
    public_key: "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd".to_string(),
    address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    network: "mainnet".to_string(),
});

let wallet_credential = service.create_credential(
    personal_identity.id,
    "Bitcoin Wallet".to_string(),
    CredentialType::CryptoWallet,
    SecurityLevel::Critical,
    &wallet_data,
).await?;
```

### 5. SSH 密钥管理

```rust
let ssh_data = CredentialData::SshKey(SshKeyData {
    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----...".to_string(),
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...".to_string(),
    key_type: "ed25519".to_string(),
    passphrase: Some("key_passphrase".to_string()),
});

let ssh_credential = service.create_credential(
    work_identity.id,
    "Production Server".to_string(),
    CredentialType::SshKey,
    SecurityLevel::High,
    &ssh_data,
).await?;
```

### 6. 服务器配置管理

```rust
let server_data = CredentialData::ServerConfig(ServerConfigData {
    hostname: "prod-server-01".to_string(),
    ip_address: Some("192.168.1.100".to_string()),
    port: 22,
    protocol: "ssh".to_string(),
    username: "admin".to_string(),
    password: Some("server_password".to_string()),
    ssh_key_id: Some(ssh_credential.id),
    additional_config: {
        let mut config = HashMap::new();
        config.insert("timeout".to_string(), "30".to_string());
        config.insert("compression".to_string(), "true".to_string());
        config
    },
});
```

### 7. 搜索和查询

```rust
// 按名称搜索凭据
let search_results = service.search_credentials("email").await?;

// 按类型获取凭据
let password_credentials = service.get_credentials_by_type(&CredentialType::Password).await?;
let crypto_wallets = service.get_credentials_by_type(&CredentialType::CryptoWallet).await?;

// 获取收藏的凭据
let favorites = service.get_favorite_credentials().await?;

// 获取特定身份的所有凭据
let identity_credentials = service.get_credentials_for_identity(&personal_identity.id).await?;

// 按身份类型获取身份
let work_identities = service.get_identities_by_type(&IdentityType::Work).await?;
```

### 8. 导出和备份

```rust
// 导出身份及其所有凭据
let export_data = service.export_identity(&personal_identity.id).await?;
println!("Identity: {}", export_data.identity.name);
println!("Credentials count: {}", export_data.credentials.len());

// 获取统计信息
let stats = service.get_statistics().await?;
println!("Total identities: {}", stats.total_identities);
println!("Total credentials: {}", stats.total_credentials);
println!("Active credentials: {}", stats.active_credentials);
```

### 9. 安全操作

```rust
// 生成强密码
let password = service.generate_password(16, true); // 16字符，包含符号
println!("Generated password: {}", password);

// 计算数据哈希
let data = b"important data";
let hash = service.hash_data(data);
println!("SHA-256 hash: {}", hex::encode(hash));

// 锁定和解锁服务
service.lock(); // 清除内存中的加密密钥
assert!(!service.is_unlocked());

service.unlock("your_master_password", &salt)?; // 重新解锁
assert!(service.is_unlocked());
```

### 10. 错误处理

```rust
use persona_core::{PersonaError, Result};

async fn handle_operations(service: &PersonaService) -> Result<()> {
    match service.get_identity(&some_id).await {
        Ok(Some(identity)) => {
            println!("Found identity: {}", identity.name);
        }
        Ok(None) => {
            println!("Identity not found");
        }
        Err(e) => {
            match e.downcast_ref::<PersonaError>() {
                Some(PersonaError::AuthenticationFailed(msg)) => {
                    eprintln!("Authentication error: {}", msg);
                }
                Some(PersonaError::CryptographicError(msg)) => {
                    eprintln!("Crypto error: {}", msg);
                }
                Some(PersonaError::Database(msg)) => {
                    eprintln!("Database error: {}", msg);
                }
                _ => {
                    eprintln!("Unknown error: {}", e);
                }
            }
        }
    }
    Ok(())
}
```

## 完整示例：密码管理器

```rust
use persona_core::*;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化
    let db = Database::from_file("password_manager.db").await?;
    db.migrate().await?;
    let mut service = PersonaService::new(db).await?;

    // 获取主密码
    print!("Enter master password: ");
    io::stdout().flush().unwrap();
    let mut master_password = String::new();
    io::stdin().read_line(&mut master_password).unwrap();
    let master_password = master_password.trim();

    let salt = service.generate_salt();
    service.unlock(master_password, &salt)?;

    // 创建默认身份
    let identity = service.create_identity(
        "Default".to_string(),
        IdentityType::Personal,
    ).await?;

    loop {
        println!("\n=== Password Manager ===");
        println!("1. Add password");
        println!("2. List passwords");
        println!("3. Search passwords");
        println!("4. Generate password");
        println!("5. Exit");
        print!("Choose option: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => add_password(&service, &identity).await?,
            "2" => list_passwords(&service, &identity).await?,
            "3" => search_passwords(&service).await?,
            "4" => generate_password(&service),
            "5" => break,
            _ => println!("Invalid option"),
        }
    }

    Ok(())
}

async fn add_password(service: &PersonaService, identity: &Identity) -> Result<()> {
    print!("Site name: ");
    io::stdout().flush().unwrap();
    let mut site_name = String::new();
    io::stdin().read_line(&mut site_name).unwrap();
    let site_name = site_name.trim();

    print!("Username: ");
    io::stdout().flush().unwrap();
    let mut username = String::new();
    io::stdin().read_line(&mut username).unwrap();
    let username = username.trim();

    print!("Password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();

    let password_data = CredentialData::Password(PasswordCredentialData {
        password: password.to_string(),
        email: Some(username.to_string()),
        security_questions: vec![],
    });

    service.create_credential(
        identity.id,
        site_name.to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        &password_data,
    ).await?;

    println!("Password saved!");
    Ok(())
}

async fn list_passwords(service: &PersonaService, identity: &Identity) -> Result<()> {
    let credentials = service.get_credentials_for_identity(&identity.id).await?;

    println!("\nSaved passwords:");
    for cred in credentials {
        println!("- {}", cred.name);
        if let Some(url) = &cred.url {
            println!("  URL: {}", url);
        }
        if let Some(username) = &cred.username {
            println!("  Username: {}", username);
        }
    }
    Ok(())
}

async fn search_passwords(service: &PersonaService) -> Result<()> {
    print!("Search term: ");
    io::stdout().flush().unwrap();
    let mut query = String::new();
    io::stdin().read_line(&mut query).unwrap();
    let query = query.trim();

    let results = service.search_credentials(query).await?;

    println!("\nSearch results:");
    for cred in results {
        println!("- {}", cred.name);
    }
    Ok(())
}

fn generate_password(service: &PersonaService) {
    let password = service.generate_password(16, true);
    println!("Generated password: {}", password);
}
```

这个示例展示了如何使用 Persona 核心库构建一个完整的密码管理器应用程序。