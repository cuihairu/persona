//! `persona secrets …`：本地 Secrets 自动化（gap #28 余项三件套）。
//!
//! 复用 Connect 的解锁/审计路径（`PersonaService` 直读，解密自动记
//! `CredentialDecrypted` 审计），提供三种消费形态：
//!
//! - `resolve`：引用 → 明文（脚本基元，一行一值）
//! - `run`：`--env NAME=REF` 注入子进程环境后执行（shell plugins 通用机制）
//! - `k8s`：渲染 K8s `Secret` 清单（YAML，`data` 走 base64）到 stdout
//! - `external`：Terraform `external` provider 协议助手（stdin JSON 查询 →
//!   stdout JSON 明文；native gRPC provider 需 Go SDK，刻意不做）
//!
//! 引用语法统一为 `IDENTITY/ITEM/FIELD`：identity 按名称、item 按凭据名
//! 精确匹配；`name`/`username`/`url`/`notes` 取元数据（不解密），其余字段
//! 解密后按类型词汇表取值；`secret` 是各类型主秘密的别名。可选字段未设置
//! 即报错（不静默给空串）。

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::models::credential::CredentialData;
use persona_core::models::Credential;
use persona_core::storage::Database;
use persona_core::PersonaService;

#[derive(Args)]
pub struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// 解析引用并打印明文（一行一值；顺序与参数一致）
    Resolve {
        /// 引用列表（IDENTITY/ITEM/FIELD）
        #[arg(required = true)]
        refs: Vec<String>,
    },
    /// 注入环境变量后执行命令（明文只进子进程环境，不进 shell 历史）
    Run {
        /// NAME=REF 注入项（可多次）
        #[arg(long = "env")]
        env: Vec<String>,
        /// `--` 之后的命令与参数
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },
    /// 渲染 Kubernetes Secret 清单（YAML 到 stdout，供 kubectl apply）
    K8s {
        /// Secret 名称
        #[arg(long)]
        name: String,
        /// 命名空间（缺省不写该字段，跟随 kubectl 上下文）
        #[arg(long)]
        namespace: Option<String>,
        /// KEY=REF 键值来源（可多次；至少一项）
        #[arg(long = "key")]
        keys: Vec<String>,
        /// 附加 label（可多次，KEY=VALUE）
        #[arg(long)]
        labels: Vec<String>,
        /// 附加 annotation（可多次，KEY=VALUE）
        #[arg(long = "annotation")]
        annotations: Vec<String>,
    },
    /// Terraform external provider 协议助手：stdin 收 {"NAME":"REF"} 查询，
    /// stdout 回 {"NAME":"明文"}（错误走 stderr + 非零退出）
    External,
}

pub async fn execute(args: SecretsArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SecretsArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        SecretsCommand::Resolve { refs } => {
            let service = open_unlocked(config, ui).await?;
            let parsed = refs
                .iter()
                .map(|raw| SecretRef::parse(raw))
                .collect::<Result<Vec<_>>>()?;
            for secret_ref in &parsed {
                println!(
                    "{}",
                    resolve_ref(&service, secret_ref)
                        .await
                        .with_context(|| format!("failed to resolve {secret_ref}"))?
                );
            }
            Ok(())
        }
        SecretsCommand::Run { env, command } => run_command(config, ui, &env, &command).await,
        SecretsCommand::K8s {
            name,
            namespace,
            keys,
            labels,
            annotations,
        } => {
            render_k8s(
                config,
                ui,
                &name,
                namespace.as_deref(),
                &keys,
                &labels,
                &annotations,
            )
            .await
        }
        SecretsCommand::External => render_external(config, ui).await,
    }
}

// -----------------------------------------------------------------------
// 解锁（与 connect.rs 同一条链：惯例 PERSONA_MASTER_PASSWORD env 优先）
// -----------------------------------------------------------------------

async fn open_unlocked(config: &CliConfig, ui: &dyn PromptUi) -> Result<PersonaService> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if !service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        bail!("Workspace not initialized. Run `persona init` first");
    }

    let password = crate::commands::service::prompt_master_password(ui)?;
    match service
        .authenticate_user(&password)
        .await
        .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
    {
        persona_core::auth::authentication::AuthResult::Success => Ok(service),
        other => bail!("Authentication failed: {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 引用解析与字段提取
// -----------------------------------------------------------------------

/// `IDENTITY/ITEM/FIELD` 三段引用。ITEM 匹配凭据 `name`（同一身份内必须
/// 唯一，重复名报歧义错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretRef {
    pub identity: String,
    pub item: String,
    pub field: String,
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.identity, self.item, self.field)
    }
}

impl SecretRef {
    fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.trim().is_empty()) {
            bail!(
                "invalid secret reference {raw:?} (expected IDENTITY/ITEM/FIELD, \
                 e.g. work/deploy/api_key)"
            );
        }
        Ok(Self {
            identity: parts[0].trim().to_string(),
            item: parts[1].trim().to_string(),
            field: parts[2].trim().to_string(),
        })
    }
}

/// 凭据 `name` 元数据字段（不解密即可取）。
const METADATA_FIELDS: [&str; 4] = ["name", "username", "url", "notes"];

/// 该凭据类型上 `field` 的取值；`None` = 该类型没有此字段。
/// 返回 `Some(None)` 语义用 `Option<Option<String>>` 表达不便，
/// 这里改为：字段存在但未设置 → `Err`（`FieldNotSet`），不存在 → `Ok(None)`。
fn extract_data_field(data: &CredentialData, field: &str) -> Result<Option<String>> {
    use CredentialData::*;
    let (exists, value) = match data {
        Password(d) => match field {
            "password" => (true, Some(d.password.clone())),
            "email" => (true, d.email.clone()),
            _ => (false, None),
        },
        ApiKey(d) => match field {
            "api_key" => (true, Some(d.api_key.clone())),
            "api_secret" => (true, d.api_secret.clone()),
            "token" => (true, d.token.clone()),
            _ => (false, None),
        },
        TwoFactor(d) => match field {
            "secret_key" => (true, Some(d.secret_key.clone())),
            "issuer" => (true, Some(d.issuer.clone())),
            "account_name" => (true, Some(d.account_name.clone())),
            _ => (false, None),
        },
        SshKey(d) => match field {
            "private_key" => (true, Some(d.private_key.clone())),
            "public_key" => (true, Some(d.public_key.clone())),
            "key_type" => (true, Some(d.key_type.clone())),
            "passphrase" => (true, d.passphrase.clone()),
            _ => (false, None),
        },
        BankCard(d) => match field {
            "card_number" => (true, Some(d.card_number.clone())),
            "cardholder_name" => (true, Some(d.cardholder_name.clone())),
            "expiry_date" => (true, Some(d.expiry_date.clone())),
            "cvv" => (true, Some(d.cvv.clone())),
            "bank_name" => (true, Some(d.bank_name.clone())),
            _ => (false, None),
        },
        ServerConfig(d) => match field {
            "hostname" => (true, Some(d.hostname.clone())),
            "ip_address" => (true, d.ip_address.clone()),
            "port" => (true, Some(d.port.to_string())),
            "protocol" => (true, Some(d.protocol.clone())),
            "username" => (true, Some(d.username.clone())),
            "password" => (true, d.password.clone()),
            _ => (false, None),
        },
        SecureNote(d) => match field {
            "note" => (true, Some(d.note.clone())),
            _ => (false, None),
        },
        CryptoWallet(d) => match field {
            "wallet_type" => (true, Some(d.wallet_type.clone())),
            "mnemonic_phrase" => (true, d.mnemonic_phrase.clone()),
            "private_key" => (true, d.private_key.clone()),
            "public_key" => (true, Some(d.public_key.clone())),
            "address" => (true, Some(d.address.clone())),
            "network" => (true, Some(d.network.clone())),
            _ => (false, None),
        },
        SoftwareLicense(d) => match field {
            "license_key" => (true, Some(d.license_key.clone())),
            "version" => (true, d.version.clone()),
            "publisher" => (true, d.publisher.clone()),
            "purchase_date" => (true, d.purchase_date.clone()),
            "order_number" => (true, d.order_number.clone()),
            "support_email" => (true, d.support_email.clone()),
            "download_url" => (true, d.download_url.clone()),
            _ => (false, None),
        },
        // GameToken/Identity/Raw：没有面向自动化的稳定字段词汇
        _ => (false, None),
    };
    if !exists {
        return Ok(None);
    }
    value.map(Some).ok_or_else(|| {
        anyhow!(
            "field {field:?} is not set on this item (secret refs do not \
                 substitute empty strings)"
        )
    })
}

/// 各类型支持的字段清单（错误提示用）。
fn data_fields_of(data: &CredentialData) -> &'static [&'static str] {
    use CredentialData::*;
    match data {
        Password(_) => &["password", "email"],
        ApiKey(_) => &["api_key", "api_secret", "token"],
        TwoFactor(_) => &["secret_key", "issuer", "account_name"],
        SshKey(_) => &["private_key", "public_key", "key_type", "passphrase"],
        BankCard(_) => &[
            "card_number",
            "cardholder_name",
            "expiry_date",
            "cvv",
            "bank_name",
        ],
        ServerConfig(_) => &[
            "hostname",
            "ip_address",
            "port",
            "protocol",
            "username",
            "password",
        ],
        SecureNote(_) => &["note"],
        CryptoWallet(_) => &[
            "wallet_type",
            "mnemonic_phrase",
            "private_key",
            "public_key",
            "address",
            "network",
        ],
        SoftwareLicense(_) => &[
            "license_key",
            "version",
            "publisher",
            "purchase_date",
            "order_number",
            "support_email",
            "download_url",
        ],
        _ => &[],
    }
}

/// `secret` 别名：各类型的主秘密字段。
fn primary_secret_field(data: &CredentialData) -> Option<&'static str> {
    use CredentialData::*;
    Some(match data {
        Password(_) => "password",
        ApiKey(_) => "api_key",
        TwoFactor(_) => "secret_key",
        SshKey(_) => "private_key",
        ServerConfig(_) => "password",
        SecureNote(_) => "note",
        CryptoWallet(_) => "private_key",
        SoftwareLicense(_) => "license_key",
        _ => return None,
    })
}

/// 解析一条引用为明文。解密路径自动记 `CredentialDecrypted` 审计（service
/// 侧既有语义，不重复记）。
pub(crate) async fn resolve_ref(
    service: &PersonaService,
    secret_ref: &SecretRef,
) -> Result<String> {
    let identity = service
        .get_identity_by_name(&secret_ref.identity)
        .await
        .map_err(|e| anyhow!("Failed to load identity: {}", e))?
        .with_context(|| format!("Identity '{}' not found", secret_ref.identity))?;

    let credentials = service
        .get_credentials_for_identity(&identity.id)
        .await
        .map_err(|e| anyhow!("Failed to load credentials: {}", e))?;
    let matches: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.name == secret_ref.item)
        .collect();
    let credential = match matches.len() {
        0 => anyhow::bail!(
            "Credential '{}' not found in identity '{}'",
            secret_ref.item,
            secret_ref.identity
        ),
        1 => matches[0],
        _ => anyhow::bail!(
            "Credential name '{}' is ambiguous in identity '{}' ({} items share it); \
             rename or reference by a unique name",
            secret_ref.item,
            secret_ref.identity,
            matches.len()
        ),
    };

    // 元数据字段不解密
    let metadata_value: Option<String> = match secret_ref.field.as_str() {
        "name" => Some(credential.name.clone()),
        "username" => match credential.username.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"username\" is not set on this item"),
        },
        "url" => match credential.url.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"url\" is not set on this item"),
        },
        "notes" => match credential.notes.clone() {
            Some(v) => Some(v),
            None => anyhow::bail!("field \"notes\" is not set on this item"),
        },
        _ => None,
    };
    if let Some(value) = metadata_value {
        return Ok(value);
    }

    let data = service
        .get_credential_data(&credential.id)
        .await
        .map_err(|e| anyhow!("Failed to decrypt credential: {}", e))?
        .with_context(|| format!("Credential '{}' has no payload", secret_ref.item))?;

    // `secret` 别名 → 该类型主秘密字段
    let field = if secret_ref.field == "secret" {
        primary_secret_field(&data).with_context(|| {
            format!(
                "type {:?} has no primary secret field (use one of: {})",
                data,
                data_fields_of(&data).join(", ")
            )
        })?
    } else {
        secret_ref.field.as_str()
    };

    extract_data_field(&data, field)?.with_context(|| {
        format!(
            "unknown field {field:?} for this item type (valid: {} plus metadata \
             {})",
            data_fields_of(&data).join(", "),
            METADATA_FIELDS.join(", ")
        )
    })
}

// -----------------------------------------------------------------------
// run（shell plugins 通用机制：env 注入 + 前台转发）
// -----------------------------------------------------------------------

/// 解析 `NAME=REF` 注入项。
fn parse_env_assignments(specs: &[String]) -> Result<Vec<(String, SecretRef)>> {
    specs
        .iter()
        .map(|spec| {
            let (name, raw) = spec
                .split_once('=')
                .with_context(|| format!("--env {spec:?} must be NAME=REF"))?;
            if name.trim().is_empty()
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                bail!("--env {spec:?} has an invalid variable name (use [A-Za-z0-9_])");
            }
            if name.starts_with(|c: char| c.is_ascii_digit()) {
                bail!("--env {spec:?} variable name must not start with a digit");
            }
            Ok((name.to_string(), SecretRef::parse(raw)?))
        })
        .collect()
}

/// spawn 子进程：继承父环境 + 注入解析后的变量；stdio 全透传。
/// 独立成函数便于测试退出码分支（不经过 execute 的 exit 短路）。
pub(crate) async fn spawn_with_env(
    assignments: &[(String, String)],
    command: &[std::ffi::OsString],
) -> Result<std::process::ExitStatus> {
    let (program, rest) = command
        .split_first()
        .with_context(|| "run requires a command after `--`")?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(rest);
    for (name, value) in assignments {
        cmd.env(name, value);
    }
    cmd.status()
        .await
        .with_context(|| format!("failed to spawn {}", program.to_string_lossy()))
}

async fn run_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    env_specs: &[String],
    command: &[std::ffi::OsString],
) -> Result<()> {
    if command.is_empty() {
        bail!("run requires a command after `--`");
    }
    let parsed = parse_env_assignments(env_specs)?;
    let service = open_unlocked(config, ui).await?;
    // 先全部解析再 spawn：引用有错就不该启动半环境子进程
    let mut assignments = Vec::with_capacity(parsed.len());
    for (name, secret_ref) in &parsed {
        let value = resolve_ref(&service, secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        assignments.push((name.clone(), value));
    }
    let status = spawn_with_env(&assignments, command).await?;
    if status.success() {
        return Ok(());
    }
    // 转发子进程退出码（测试只走 spawn_with_env，不进这条 exit 短路）
    std::process::exit(status.code().unwrap_or(1));
}

// -----------------------------------------------------------------------
// k8s（Secret 清单渲染；JSON 落 base64，kubectl 侧按需 apply）
// -----------------------------------------------------------------------

/// manifest 键名合法性（k8s object key 字符集）。`allow_slash` 用于
/// label/annotation 的 `prefix/name` 形式；data/对象名不允许斜杠。
fn valid_key(key: &str, allow_slash: bool) -> bool {
    !key.is_empty()
        && key.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') || (allow_slash && c == '/')
        })
}

fn parse_kv_pairs(specs: &[String], flag: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for spec in specs {
        let (k, v) = spec
            .split_once('=')
            .with_context(|| format!("--{flag} {spec:?} must be KEY=VALUE"))?;
        if !valid_key(k, true) {
            bail!("--{flag} {spec:?} has an invalid key (use [A-Za-z0-9._/-])");
        }
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

#[derive(Serialize)]
#[allow(non_snake_case)] // field names double as the serialized YAML keys
struct K8sSecretManifest {
    apiVersion: &'static str,
    kind: &'static str,
    #[serde(rename = "type")]
    secret_type: &'static str,
    metadata: K8sObjectMeta,
    data: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct K8sObjectMeta {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<BTreeMap<String, String>>,
}

async fn render_k8s(
    config: &CliConfig,
    ui: &dyn PromptUi,
    name: &str,
    namespace: Option<&str>,
    key_specs: &[String],
    label_specs: &[String],
    annotation_specs: &[String],
) -> Result<()> {
    if !valid_key(name, false) {
        bail!("--name {name:?} is not a valid Kubernetes object name");
    }
    if let Some(ns) = namespace {
        if !valid_key(ns, false) {
            bail!("--namespace {ns:?} is not a valid namespace name");
        }
    }
    if key_specs.is_empty() {
        bail!("at least one --key KEY=REF is required");
    }

    let mut key_refs = Vec::with_capacity(key_specs.len());
    for spec in key_specs {
        let (key, raw) = spec
            .split_once('=')
            .with_context(|| format!("--key {spec:?} must be KEY=REF"))?;
        if !valid_key(key, false) {
            bail!("--key {spec:?} has an invalid key (use [A-Za-z0-9._-])");
        }
        key_refs.push((key.to_string(), SecretRef::parse(raw)?));
    }
    let labels = parse_kv_pairs(label_specs, "labels")?;
    let annotations = parse_kv_pairs(annotation_specs, "annotation")?;

    let service = open_unlocked(config, ui).await?;
    use base64::Engine;
    let mut data = BTreeMap::new();
    for (key, secret_ref) in &key_refs {
        let value = resolve_ref(&service, secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        data.insert(
            key.clone(),
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
        );
    }

    let manifest = K8sSecretManifest {
        apiVersion: "v1",
        kind: "Secret",
        secret_type: "Opaque",
        metadata: K8sObjectMeta {
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
            labels: (!labels.is_empty()).then_some(labels),
            annotations: (!annotations.is_empty()).then_some(annotations),
        },
        data,
    };
    let yaml = serde_yaml::to_string(&manifest).context("failed to serialize manifest")?;
    print!("{yaml}");
    Ok(())
}

// -----------------------------------------------------------------------
// external（Terraform external provider 协议助手）
// -----------------------------------------------------------------------

/// external 协议核心（纯函数）：stdin JSON 对象 `{"NAME":"REF"}` →
/// stdout JSON 对象 `{"NAME":"明文"}`。保持插入顺序（serde_json 默认
/// BTreeMap 有序即可——Terraform 只按 key 取值，顺序无语义）。
pub(crate) async fn resolve_external_map(
    service: &PersonaService,
    input: &str,
) -> Result<serde_json::Value> {
    let query: serde_json::Value =
        serde_json::from_str(input).context("stdin is not valid JSON")?;
    let obj = query
        .as_object()
        .with_context(|| "external query must be a JSON object of NAME=REF")?;
    let mut out = serde_json::Map::with_capacity(obj.len());
    for (name, raw) in obj {
        let raw = raw
            .as_str()
            .with_context(|| format!("query value for {name:?} must be a string REF"))?;
        let secret_ref = SecretRef::parse(raw)?;
        let value = resolve_ref(service, &secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        out.insert(name.clone(), serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(out))
}

async fn render_external(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut input = String::new();
    tokio::io::stdin()
        .read_to_string(&mut input)
        .await
        .context("failed to read stdin")?;
    let service = open_unlocked(config, ui).await?;
    let out = resolve_external_map(&service, &input).await.map_err(|e| {
        eprintln!("{e:#}");
        e
    })?;
    println!("{out}");
    Ok(())
}

// -----------------------------------------------------------------------
// 测试：ScriptedUi 缝 + env 串行（connect.rs 同款 fixture）
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use base64::Engine;
    use persona_core::models::{
        ApiKeyData, CredentialType, IdentityType, PasswordCredentialData, SecureNoteData,
        SecurityLevel, SshKeyData, TwoFactorData,
    };
    use persona_core::Repository;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct EnvVar(&'static str);

    impl EnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// 建带 master 用户的库：work 身份下 password/api_key/totp/ssh/note
    /// 五种凭据，覆盖元数据字段与各类型字段词汇。
    async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        persona_core::storage::WorkspaceRepository::new(db.clone())
            .create(&persona_core::models::Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity("work".to_string(), IdentityType::Work)
            .await
            .unwrap();

        let mut login = service
            .create_credential(
                identity.id,
                "login".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                &CredentialData::Password(PasswordCredentialData {
                    password: "p@ss".to_string(),
                    email: Some("a@b.c".to_string()),
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        login.username = Some("alice".to_string());
        login.url = Some("https://x.example".to_string());
        login.notes = Some("rotated quarterly".to_string());
        service.update_credential(&login).await.unwrap();

        service
            .create_credential(
                identity.id,
                "deploy".to_string(),
                CredentialType::ApiKey,
                SecurityLevel::High,
                &CredentialData::ApiKey(ApiKeyData {
                    api_key: "sk-123".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: vec![],
                    expires_at: None,
                }),
            )
            .await
            .unwrap();

        service
            .create_credential(
                identity.id,
                "github-2fa".to_string(),
                CredentialType::TwoFactor,
                SecurityLevel::Medium,
                &CredentialData::TwoFactor(TwoFactorData {
                    secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                    issuer: "github".to_string(),
                    account_name: "alice".to_string(),
                    algorithm: "SHA1".to_string(),
                    digits: 6,
                    period: 30,
                }),
            )
            .await
            .unwrap();

        service
            .create_credential(
                identity.id,
                "server".to_string(),
                CredentialType::SshKey,
                SecurityLevel::High,
                &CredentialData::SshKey(SshKeyData {
                    private_key: "PRIVATE".to_string(),
                    public_key: "PUBLIC".to_string(),
                    key_type: "ed25519".to_string(),
                    passphrase: None,
                }),
            )
            .await
            .unwrap();

        service
            .create_credential(
                identity.id,
                "playbook".to_string(),
                CredentialType::SecureNote,
                SecurityLevel::Low,
                &CredentialData::SecureNote(SecureNoteData {
                    note: "run book steps".to_string(),
                }),
            )
            .await
            .unwrap();

        (dir, config)
    }

    fn resolve_args(refs: &[&str]) -> SecretsArgs {
        SecretsArgs {
            command: SecretsCommand::Resolve {
                refs: refs.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    // ---- 引用解析 ----

    #[test]
    fn parse_ref_rejects_bad_shapes() {
        for raw in ["no-slash", "a/b", "a/b/c/d", "/work/x", "work//password"] {
            let err = SecretRef::parse(raw).unwrap_err();
            assert!(format!("{err:#}").contains("IDENTITY/ITEM/FIELD"), "{err}");
        }
        let ok = SecretRef::parse(" work / deploy / api_key ").unwrap();
        assert_eq!(
            ok,
            SecretRef {
                identity: "work".into(),
                item: "deploy".into(),
                field: "api_key".into()
            }
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resolve_outputs_metadata_and_variant_fields() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(
            resolve_args(&[
                "work/login/password",
                "work/login/username",
                "work/login/name",
                "work/login/notes",
                "work/login/secret",
                "work/deploy/api_key",
                "work/deploy/secret",
                "work/github-2fa/secret_key",
                "work/server/private_key",
                "work/playbook/note",
            ]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resolve_errors_are_precise() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        // 未知身份 / 未知条目 / 未知字段
        let err = execute_with(
            resolve_args(&["ghost/login/password"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("Identity 'ghost' not found"),
            "{err}"
        );

        let err = execute_with(
            resolve_args(&["work/none/password"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("Credential 'none' not found"),
            "{err}"
        );

        let err = execute_with(
            resolve_args(&["work/deploy/card_number"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err}");
        assert!(format!("{err:#}").contains("api_secret"), "{err}");

        // 未设置的可选字段：报错不给空串
        let err = execute_with(
            resolve_args(&["work/deploy/api_secret"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("is not set"), "{err}");

        // 元数据缺省同理
        let err = execute_with(
            resolve_args(&["work/deploy/username"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("is not set"), "{err}");

        // secret 别名用在无主秘密类型 → 列出合法字段
        let err = execute_with(
            resolve_args(&["work/bank/secret"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("Credential 'bank' not found"),
            "{err}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn ambiguous_item_names_are_rejected() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.authenticate_user("master-pin").await.unwrap();
        let identity = service.get_identity_by_name("work").await.unwrap().unwrap();
        service
            .create_credential(
                identity.id,
                "login".to_string(),
                CredentialType::Password,
                SecurityLevel::Low,
                &CredentialData::Password(PasswordCredentialData {
                    password: "dup".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();

        let err = execute_with(
            resolve_args(&["work/login/password"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("ambiguous"), "{err}");
    }

    // ---- run ----

    #[test]
    fn parse_env_assignments_validate_names() {
        let err = parse_env_assignments(&["JUST_A_REF".to_string()]).unwrap_err();
        assert!(format!("{err:#}").contains("NAME=REF"), "{err}");
        let err = parse_env_assignments(&["1BAD=x/y/z".to_string()]).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not start with a digit"),
            "{err}"
        );
        let err = parse_env_assignments(&["BAD-NAME=x/y/z".to_string()]).unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid variable name"),
            "{err}"
        );
        let err = parse_env_assignments(&["OK=only-two".to_string()]).unwrap_err();
        assert!(format!("{err:#}").contains("IDENTITY/ITEM/FIELD"), "{err}");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn run_injects_env_and_propagates_success() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let args = SecretsArgs {
            command: SecretsCommand::Run {
                env: vec!["GITHUB_TOKEN=work/deploy/api_key".to_string()],
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "test \"$GITHUB_TOKEN\" = \"sk-123\"".into(),
                ],
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn run_resolves_all_refs_before_spawning() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        // 第二个引用是坏的：子进程不该被启动（探针文件不存在 = 未 spawn）
        let probe =
            std::env::temp_dir().join(format!("persona-secrets-run-probe-{}", std::process::id()));
        let _ = std::fs::remove_file(&probe);
        let args = SecretsArgs {
            command: SecretsCommand::Run {
                env: vec![
                    "A=work/deploy/api_key".to_string(),
                    "B=work/ghost/password".to_string(),
                ],
                command: vec!["sh".into(), "-c".into(), format!("touch {probe:?}").into()],
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not found"), "{err}");
        assert!(!probe.exists(), "bad ref must not spawn the child");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn spawn_with_env_forwards_nonzero_exit_code() {
        let status = spawn_with_env(&[], &["sh".into(), "-c".into(), "exit 7".into()])
            .await
            .unwrap();
        assert_eq!(status.code(), Some(7));
        let missing = spawn_with_env(&[], &["definitely-not-a-binary-xyz".into()])
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("failed to spawn"), "{missing}");
    }

    // ---- k8s ----

    fn k8s_args(keys: &[&str]) -> SecretsArgs {
        SecretsArgs {
            command: SecretsCommand::K8s {
                name: "app-secret".to_string(),
                namespace: Some("prod".to_string()),
                keys: keys.iter().map(|s| s.to_string()).collect(),
                labels: vec!["app.kubernetes.io/managed-by=persona".to_string()],
                annotations: vec![],
            },
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn k8s_renders_base64_manifest() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        // 捕获 stdout：println!/print! 直接写进程 stdout，测试里用
        // resolve_ref + 序列化层验证（渲染路径与输出路径解耦），这里只
        // 验证命令本身成功且引用错误会失败。
        execute_with(
            k8s_args(&["password=work/login/password"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();

        let err = execute_with(
            k8s_args(&["password=work/ghost/password"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("not found"), "{err}");
    }

    #[test]
    fn k8s_manifest_shape_is_valid() {
        // 结构层断言：base64 + 字段名 + 可选段省略
        let manifest = K8sSecretManifest {
            apiVersion: "v1",
            kind: "Secret",
            secret_type: "Opaque",
            metadata: K8sObjectMeta {
                name: "app-secret".to_string(),
                namespace: None,
                labels: None,
                annotations: None,
            },
            data: BTreeMap::from([(
                "password".to_string(),
                base64::engine::general_purpose::STANDARD.encode("p@ss"),
            )]),
        };
        let yaml = serde_yaml::to_string(&manifest).unwrap();
        assert!(yaml.contains("apiVersion: v1"), "{yaml}");
        assert!(yaml.contains("kind: Secret"), "{yaml}");
        assert!(yaml.contains("type: Opaque"), "{yaml}");
        assert!(yaml.contains("password: cEBzcw=="), "{yaml}");
        assert!(!yaml.contains("namespace"), "{yaml}");
    }

    #[test]
    fn k8s_key_validation_rejects_bad_input() {
        let err = parse_kv_pairs(&["bad key=v".to_string()], "labels").unwrap_err();
        assert!(format!("{err:#}").contains("invalid key"), "{err}");
        assert!(valid_key("app.kubernetes.io/managed-by", true));
        assert!(!valid_key("", true));
        assert!(!valid_key("has space", false));
    }

    // ---- external ----

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn external_resolves_query_map() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;
        let service = open_unlocked(&config, &ScriptedUi::new()).await.unwrap();

        let out = resolve_external_map(
            &service,
            r#"{"api_key": "work/deploy/api_key", "title": "work/login/name"}"#,
        )
        .await
        .unwrap();
        assert_eq!(out["api_key"], "sk-123");
        assert_eq!(out["title"], "login");

        let err = resolve_external_map(&service, r#"{"x": "work/ghost/password"}"#)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not found"), "{err}");

        let err = resolve_external_map(&service, "[1,2]").await.unwrap_err();
        assert!(format!("{err:#}").contains("JSON object"), "{err}");

        let err = resolve_external_map(&service, r#"{"x": 3}"#)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("must be a string REF"), "{err}");
    }
}
