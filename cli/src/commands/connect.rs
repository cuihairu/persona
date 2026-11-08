//! `persona connect …`：Connect 本机自动化（token 管理 + serve）。
//!
//! 门禁与 scope 判定都在 core（`persona_core::connect` + service 方法群），
//! HTTP 面在独立 crate（`persona_connect_server`，与桌面共用同一 router/
//! 三防线/限额）。本模块只做编排：解锁、scope 参数解析、一次性明文展示、
//! 前台 serve（Ctrl-C 退出，不做 daemon 化——DR-1 A2，systemd 用户单元由
//! 用户自配）。主密码解析走 service.rs 的惯例（`PERSONA_MASTER_PASSWORD`
//! env 优先），serve 另支持 `--passphrase-env VAR`（显式变量必须已设且
//! 非空，不静默回退）。

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};
use persona_core::storage::Database;
use persona_core::PersonaService;

#[derive(Args)]
pub struct ConnectArgs {
    #[command(subcommand)]
    command: ConnectCommand,
}

#[derive(Subcommand)]
enum ConnectCommand {
    /// 管理 Connect token（明文只在创建时展示一次）
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// 前台启动 Connect listener（loopback TCP 或 unix socket，Ctrl-C 退出）
    Serve {
        /// 监听端口（默认 0 = 由 OS 分配；仅 TCP 传输）
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// 改用 Unix domain socket（0600 文件 + 属主 uid 校验；可带路径，
        /// 缺省 $XDG_RUNTIME_DIR/persona/connect.sock，无 XDG_RUNTIME_DIR
        /// 时退 ~/.persona/connect.sock）。与 --port 互斥；Windows 上报错
        #[arg(long, value_name = "PATH", num_args = 0..=1)]
        unix_socket: Option<Option<std::path::PathBuf>>,
        /// 从指定环境变量读主密码（必须已设且非空）
        #[arg(long)]
        passphrase_env: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// 创建 token：scope 用「缺省 = 全部」语义，给了限定就收窄
    Create {
        /// token 名称（如 "我的 CI 脚本"）
        #[arg(long)]
        label: String,
        /// 限定可读身份（按名称，可多次；缺省 = 全部身份）
        #[arg(long = "identity")]
        identities: Vec<String>,
        /// 限定可读条目类型（snake_case，可多次；缺省 = 全部可授权类型）
        #[arg(long = "type")]
        item_types: Vec<String>,
        /// 有效期时长（<正整数><s|m|h|d>，如 30d / 12h / 30m；缺省 = 永不过期）
        #[arg(long = "expires-in")]
        expires_in: Option<String>,
    },
    /// 列出 token（含已吊销；只有指纹，明文不可找回）
    List,
    /// 吊销 token（即时生效、幂等；接受 id 或指纹）
    Revoke {
        /// token id（UUID）或指纹（列表里展示的 hex）
        target: String,
    },
}

pub async fn execute(args: ConnectArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ConnectArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        ConnectCommand::Token { command } => match command {
            TokenCommand::Create {
                label,
                identities,
                item_types,
                expires_in,
            } => {
                create_token(
                    config,
                    ui,
                    &label,
                    &identities,
                    &item_types,
                    expires_in.as_deref(),
                )
                .await
            }
            TokenCommand::List => list_tokens(config, ui).await,
            TokenCommand::Revoke { target } => revoke_token(config, ui, &target).await,
        },
        ConnectCommand::Serve {
            port,
            unix_socket,
            passphrase_env,
        } => serve(config, ui, port, unix_socket, passphrase_env.as_deref()).await,
    }
}

// -----------------------------------------------------------------------
// 解锁（serve 的 --passphrase-env 显式变量优先；token 子命令走惯例链）
// -----------------------------------------------------------------------

/// 打开库 + 迁移 + 构造 service 并解锁（认证失败/未初始化即 bail）。
async fn open_unlocked(
    config: &CliConfig,
    ui: &dyn PromptUi,
    passphrase_env: Option<&str>,
) -> Result<PersonaService> {
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

    let password = match passphrase_env {
        Some(var) => std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"))?,
        None => crate::commands::service::prompt_master_password(ui)?,
    };
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
// token 管理
// -----------------------------------------------------------------------

/// scope 词汇表解析：与 core `ConnectItemType` 的 serde snake_case 一致。
/// 错误消息列出全部合法值（fail-fast，不猜最近邻）。
fn parse_item_type(raw: &str) -> Result<ConnectItemType> {
    let value = serde_json::Value::String(raw.to_string());
    serde_json::from_value(value).map_err(|_| {
        anyhow!(
            "unknown item type {raw:?} (valid: password, api_key, totp, note, \
                 bank_card, server_config, certificate, game_account, identity, \
                 software_license)"
        )
    })
}

/// 解析 `--expires-in` 时长：`<正整数><s|m|h|d>`（如 `30d`、`12h`、`30m`）。
/// 从创建时刻起算的相对时长；缺省不传 = 永不过期（沿用既有语义）。
fn parse_expires_in(raw: &str) -> Result<chrono::Duration> {
    let Some(idx) = raw.find(|c: char| !c.is_ascii_digit()) else {
        bail!("invalid duration {raw:?}: expected <number><unit> like 30d, 12h, 30m");
    };
    let (digits, unit) = raw.split_at(idx);
    let amount: i64 = digits
        .parse()
        .map_err(|_| anyhow!("invalid duration {raw:?}: number out of range"))?;
    if amount <= 0 {
        bail!("invalid duration {raw:?}: must be positive");
    }
    let multiplier: i64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => bail!("invalid duration {raw:?}: unknown unit {other:?} (valid: s, m, h, d)"),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("invalid duration {raw:?}: out of range"))?;
    chrono::Duration::try_seconds(seconds)
        .ok_or_else(|| anyhow!("invalid duration {raw:?}: out of range"))
}

fn type_name(t: &ConnectItemType) -> &'static str {
    match t {
        ConnectItemType::Password => "password",
        ConnectItemType::ApiKey => "api_key",
        ConnectItemType::Totp => "totp",
        ConnectItemType::Note => "note",
        ConnectItemType::BankCard => "bank_card",
        ConnectItemType::ServerConfig => "server_config",
        ConnectItemType::Certificate => "certificate",
        ConnectItemType::GameAccount => "game_account",
        ConnectItemType::Identity => "identity",
        ConnectItemType::SoftwareLicense => "software_license",
    }
}

/// scope 摘要（与桌面列表同信息量）：身份 + 类型 + 只读。
fn scope_summary(scope: &ConnectTokenScope) -> String {
    let identity_part = if scope.identities.is_empty() {
        "all identities".to_string()
    } else {
        format!("{} identit{}", scope.identities.len(), {
            if scope.identities.len() == 1 {
                "y"
            } else {
                "ies"
            }
        })
    };
    let type_part = if scope.item_types.is_empty() {
        "all types".to_string()
    } else {
        scope
            .item_types
            .iter()
            .map(type_name)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{identity_part} · {type_part} · read-only")
}

async fn create_token(
    config: &CliConfig,
    ui: &dyn PromptUi,
    label: &str,
    identity_names: &[String],
    item_types: &[String],
    expires_in: Option<&str>,
) -> Result<()> {
    let label = label.trim();
    if label.is_empty() {
        bail!("--label must not be blank");
    }
    if label.len() > 128 {
        bail!("--label must be at most 128 bytes");
    }

    // 类型/时长解析在解锁之前：参数错了就不该问密码
    let types = item_types
        .iter()
        .map(|raw| parse_item_type(raw))
        .collect::<Result<Vec<_>>>()?;
    let ttl = expires_in.map(parse_expires_in).transpose()?;

    let service = open_unlocked(config, ui, None).await?;

    let mut identity_ids = Vec::new();
    for name in identity_names {
        let identity = service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        identity_ids.push(identity.id);
    }

    let scope = ConnectTokenScope {
        identities: identity_ids,
        item_types: types,
        verbs: vec![ConnectVerb::Read],
    };
    let (token, row) = service
        .create_connect_token(
            label.to_string(),
            scope,
            None,
            ttl.map(|d| chrono::Utc::now() + d),
        )
        .await
        .into_anyhow()
        .context("failed to create connect token")?;

    println!("{}", "🔑 Connect token created".cyan().bold());
    println!("{}", token.green().bold());
    println!(
        "{}",
        "⚠️  Copy it now — the plaintext is shown only once and cannot be recovered.".yellow()
    );
    println!("   label:      {label}");
    println!("   id:         {}", row.id);
    println!("   fingerprint: {}", row.fingerprint);
    println!("   scope:      {}", scope_summary(&row.scope));
    match row.expires_at {
        Some(at) => println!("   expires at: {}", at.to_rfc3339()),
        None => {
            println!("   expires at: never (pass --expires-in <n><s|m|h|d> to bound the lifetime)")
        }
    }
    println!(
        "   {}",
        "Point your tool at http://127.0.0.1:<port>/api/v1/connect/ with".bright_black()
    );
    println!(
        "   {}",
        "`Authorization: Bearer <token>`; start the listener with `persona connect serve`."
            .bright_black()
    );
    Ok(())
}

async fn list_tokens(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let service = open_unlocked(config, ui, None).await?;
    let tokens = service
        .list_connect_tokens()
        .await
        .into_anyhow()
        .context("failed to list connect tokens")?;

    println!("{}", "🔑 Connect tokens".cyan().bold());
    if tokens.is_empty() {
        println!("(none) — create one with `persona connect token create`");
        return Ok(());
    }
    for row in tokens {
        let expired = row.expired();
        let state = if row.revoked_at.is_some() {
            "revoked".red()
        } else if expired {
            "expired".yellow()
        } else {
            "active".green()
        };
        println!(
            "{}  {:<24} {}  {}",
            state,
            row.label,
            row.fingerprint.bright_black(),
            scope_summary(&row.scope)
        );
        println!("    id: {}  {}", row.id, {
            match (&row.last_used_at, &row.revoked_at) {
                (_, Some(at)) => format!("revoked at {}", at.to_rfc3339()),
                (Some(at), None) => format!("last used {}", at.to_rfc3339()),
                (None, None) => "never used".to_string(),
            }
        });
        if let Some(at) = row.expires_at {
            if row.revoked_at.is_none() {
                println!("    expires at: {}", at.to_rfc3339());
            }
        }
    }
    Ok(())
}

async fn revoke_token(config: &CliConfig, ui: &dyn PromptUi, target: &str) -> Result<()> {
    let service = open_unlocked(config, ui, None).await?;

    // UUID 按 id；否则按指纹精确匹配（列表展示的就是指纹，复制即用）
    let id = match uuid::Uuid::parse_str(target) {
        Ok(id) => id,
        Err(_) => {
            let hit = service
                .list_connect_tokens()
                .await
                .into_anyhow()
                .context("failed to list connect tokens")?
                .into_iter()
                .find(|row| row.fingerprint == target)
                .with_context(|| format!("no token with id or fingerprint {target:?}"))?;
            hit.id
        }
    };
    let already_revoked = !service
        .revoke_connect_token(&id)
        .await
        .into_anyhow()
        .context("failed to revoke connect token")?;
    // 幂等：core 对已吊销 token 返回 false（且不重复记审计）——照实说
    if already_revoked {
        println!(
            "{}",
            format!("Token {id} was already revoked (no-op)").yellow()
        );
    } else {
        println!("{}", format!("✓ Token {id} revoked").green());
    }
    Ok(())
}

// -----------------------------------------------------------------------
// serve（DR-1 A2：前台进程 + Ctrl-C，不做 daemon 化）
// -----------------------------------------------------------------------

async fn serve(
    config: &CliConfig,
    ui: &dyn PromptUi,
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    // 构造即注册 SIGTERM（在起监听之前）：此后任何时刻的 systemd stop / kill
    // 都进同一条优雅关停路径，消灭「默认信号杀进程 → unix socket 残骸」窗口。
    let shutdown = shutdown_signal()?;
    serve_until(config, ui, port, unix_socket, passphrase_env, shutdown).await
}

/// 生产关停信号 future。SIGTERM 与 Ctrl-C 二选一即返回 `Ok(())`。
///
/// - **SIGTERM**：`shutdown_signal()` 构造时同步装好 OS handler（tokio
///   `signal()` 的 `signal_enable` 是构造期调用）——serve() 在监听启动前
///   调用本函数，SIGTERM 在进程任何阶段都被接管；若信号发生在解锁期间，
///   tokio 的 watch 通道缓存该投递，`shutdown.await` 一到即处理（优雅、
///   不丢、不产生残骸）。
/// - **Ctrl-C(SIGINT)**：刻意保持惰性（select 首次 poll 才注册）。console
///   的密码提示只清 ECHO、ISIG 仍开启——若提示期间就接管 SIGINT，用户的
///   Ctrl-C 会被 tokio 吞掉、提示无法取消。代价：解锁窗口内的 Ctrl-C 仍是
///   默认退出，可能留 socket 残骸，由下次启动按陈旧接管自愈（已实测）。
fn shutdown_signal() -> Result<impl std::future::Future<Output = Result<()>>> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                r = tokio::signal::ctrl_c() => r.context("failed to listen for Ctrl-C"),
                _ = term.recv() => Ok(()),
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            tokio::signal::ctrl_c()
                .await
                .context("failed to listen for Ctrl-C")
        })
    }
}

/// `serve` 主体，「等待退出信号」参数化——这是测试缝：生产喂 Ctrl-C，
/// 测试喂可控 future，使 解锁 → start → 打印端点 → stop → 清理 全路径
/// 可被单测执行（否则 serve 只能在真实终端手工冒烟）。
async fn serve_until<F>(
    config: &CliConfig,
    ui: &dyn PromptUi,
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
    passphrase_env: Option<&str>,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    let transport = resolve_transport(port, unix_socket)?;
    // 先起监听、后解锁：health 立即可探测（argon2 解锁的秒级延迟不再挡在
    // fleet 探针前面）；解锁完成前数据面如实 503 vault_locked——与「保险库
    // 锁定」同一语义，EXTERNAL_INTEGRATION 的重试纪律（503 退避重试）已覆盖
    // 该窗口，消费者无需感知「正在输密码」这种中间态。
    let slot = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let handle =
        persona_connect_server::start_connect_server_with_transport(slot.clone(), transport)
            .await?;
    match &handle.socket_path {
        Some(path) => {
            println!(
                "{}",
                format!(
                    "🔌 Connect listener on unix://{} (0600 + uid-checked) — Ctrl-C to stop",
                    path.display()
                )
                .cyan()
                .bold()
            );
            println!(
                "{}",
                format!(
                    "   probe: curl --unix-socket {} http://localhost/api/v1/connect/health",
                    path.display()
                )
                .bright_black()
            );
        }
        None => {
            println!(
                "{}",
                format!(
                    "🔌 Connect listener on http://127.0.0.1:{} — Ctrl-C to stop",
                    handle.port
                )
                .cyan()
                .bold()
            );
        }
    }
    // 解锁（监听已就绪）。失败：先优雅关停（等端口/socket 真释放）再原样
    // 上抛——不留「报错退出但 listener 还挂着」的半初始化状态。
    let service = match open_unlocked(config, ui, passphrase_env).await {
        Ok(service) => service,
        Err(err) => {
            handle.stop_and_wait().await;
            return Err(err);
        }
    };
    *slot.lock().await = Some(service);

    shutdown.await?;
    // stop_and_wait：等 listener 任务完成（serve 循环退出 + socket 文件已删）。
    // fire-and-forget 的 stop 在随后的进程退出竞态里可能丢掉清理任务。
    handle.stop_and_wait().await;
    println!("{}", "Connect listener stopped".bright_black());
    Ok(())
}

/// `serve` 旗标 → 传输层（纯函数，单测入口）。
///
/// - 未给 `--unix-socket` → loopback TCP（`--port`，0 = OS 分配）；
/// - `--unix-socket` 裸用 → unix socket，路径取 [`default_socket_path`]；
/// - `--unix-socket <path>` → unix socket，指定路径；
/// - `--port`（非 0）+ `--unix-socket` 同时给 → 报错（unix 无 TCP 端口，
///   静默忽略任一侧都会让调用方对着错误端点排查）。
fn resolve_transport(
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
) -> Result<persona_connect_server::ConnectTransport> {
    match unix_socket {
        None => Ok(persona_connect_server::ConnectTransport::Tcp { port }),
        Some(explicit) => {
            if port != 0 {
                anyhow::bail!(
                    "--port cannot be combined with --unix-socket (a unix socket has no TCP port)"
                );
            }
            // Windows：在解锁之前就拒（fail-fast——先要主密码再报「平台不支持」
            // 是把能力边界藏在交互后面）。库侧 start_connect_server_with_transport
            // 仍保留同语义兜底（任何调用方都能传 Unix，库必须自卫）。
            #[cfg(not(unix))]
            {
                let _ = explicit;
                anyhow::bail!(
                    "unix socket transport is not supported on this platform; \
                     use TCP loopback instead (drop --unix-socket)"
                );
            }
            #[cfg(unix)]
            {
                let path = explicit.unwrap_or_else(default_socket_path);
                Ok(persona_connect_server::ConnectTransport::Unix { path })
            }
        }
    }
}

/// `--unix-socket` 裸用时的缺省路径。
///
/// 首选 `$XDG_RUNTIME_DIR/persona/connect.sock`（XDG 运行时目录随会话
/// 登出清理、0700 属主私有）；无 XDG_RUNTIME_DIR（SSH/非 XDG 环境、
/// macOS、Windows 回退分支）时退 `~/.persona/connect.sock`（与 connect.port
/// 同目录，消费者约定的本机位置）。
///
/// Windows 上无生产调用方（resolve_transport 的 unix 分支 cfg(unix)），但
/// 单测仍在此验证回退形态（openclaw 实机抓过斜杠断言 bug）——条件 allow
/// 而非 cfg 掉，保住跨平台形状覆盖。
#[cfg_attr(not(unix), allow(dead_code))]
fn default_socket_path() -> std::path::PathBuf {
    socket_path_from(dirs::runtime_dir(), dirs::home_dir())
}

/// [`default_socket_path`] 的纯函数内核（单测入口）：runtime 目录在 →
/// `$runtime/persona/connect.sock`；否则 `$home/.persona/connect.sock`；
/// home 也不可得 → `./.persona/connect.sock`（相对路径随 cwd，仅剩的兜底）。
fn socket_path_from(
    runtime_dir: Option<std::path::PathBuf>,
    home_dir: Option<std::path::PathBuf>,
) -> std::path::PathBuf {
    if let Some(runtime) = runtime_dir {
        return runtime.join("persona").join("connect.sock");
    }
    home_dir
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".persona")
        .join("connect.sock")
}

// -----------------------------------------------------------------------
// 测试：ScriptedUi 缝 + env 串行（travel.rs 同款 fixture）
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{IdentityType, Workspace};
    use persona_core::storage::WorkspaceRepository;
    use persona_core::Repository;

    /// 进程 env 是单槽：与 bridge/switch/ssh/backup/travel 的 env 测试
    /// 共用全局锁串行（poisoned 恢复防级联）。
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

    /// 建带 master 用户的库（含一个 identity + 一条密码凭据）。
    async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
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
        service
            .create_credential(
                identity.id,
                "login".to_string(),
                persona_core::models::CredentialType::Password,
                persona_core::models::SecurityLevel::High,
                &persona_core::models::CredentialData::Password(
                    persona_core::models::PasswordCredentialData {
                        password: "secret".to_string(),
                        email: None,
                        security_questions: vec![],
                    },
                ),
            )
            .await
            .unwrap();
        (dir, config)
    }

    fn create_args(label: &str, identities: &[&str], types: &[&str]) -> ConnectArgs {
        create_args_with_ttl(label, identities, types, None)
    }

    fn create_args_with_ttl(
        label: &str,
        identities: &[&str],
        types: &[&str],
        expires_in: Option<&str>,
    ) -> ConnectArgs {
        ConnectArgs {
            command: ConnectCommand::Token {
                command: TokenCommand::Create {
                    label: label.to_string(),
                    identities: identities.iter().map(|s| s.to_string()).collect(),
                    item_types: types.iter().map(|s| s.to_string()).collect(),
                    expires_in: expires_in.map(|s| s.to_string()),
                },
            },
        }
    }

    async fn token_rows(config: &CliConfig) -> Vec<persona_core::connect::ConnectTokenRow> {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        persona_core::storage::ConnectTokenRepository::new(db)
            .list_all()
            .await
            .unwrap()
    }

    async fn audit_count(config: &CliConfig, action: &str) -> i64 {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(1) FROM audit_logs WHERE action = '{action}'"
        )))
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_shows_plaintext_once_and_persists_hashed_row() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let ui = ScriptedUi::new();
        execute_with(create_args("ci", &[], &[]), &config, &ui)
            .await
            .unwrap();

        // 库里只有哈希行；明文 pconn_ 不落库
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hash.len(), 64);
        assert!(!rows[0].hash.contains("pconn_"));
        assert_eq!(rows[0].fingerprint.len(), 16);
        assert!(rows[0].scope.identities.is_empty(), "缺省 = 全部身份");
        assert!(rows[0].scope.item_types.is_empty(), "缺省 = 全部类型");
        assert_eq!(audit_count(&config, "connect_token_created").await, 1);
        assert!(rows[0].expires_at.is_none(), "缺省 = 永不过期");
    }

    /// `--expires-in` 解析：<正整数><s|m|h|d>；0/负数/空数字/未知单位/
    /// 溢出一律拒绝。
    #[test]
    fn expires_in_parses_units_and_rejects_bad_input() {
        assert_eq!(parse_expires_in("45s").unwrap().num_seconds(), 45);
        assert_eq!(parse_expires_in("30m").unwrap().num_seconds(), 1800);
        assert_eq!(parse_expires_in("12h").unwrap().num_seconds(), 43200);
        assert_eq!(parse_expires_in("30d").unwrap().num_seconds(), 2_592_000);

        for bad in ["", "d", "0d", "-5h", "1x", "1h30m", "99999999999999999999d"] {
            assert!(parse_expires_in(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// 带 `--expires-in` 创建：行内 expires_at 落在未来约 1h（±容差），
    /// 明文行不落库语义不变。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_expires_in_persists_future_expiry() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(
            create_args_with_ttl("ttl-ci", &[], &[], Some("1h")),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();

        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        let expires_at = rows[0].expires_at.expect("expiry must be persisted");
        let delta = expires_at - chrono::Utc::now();
        assert!(
            delta.num_seconds() > 3500 && delta.num_seconds() <= 3600,
            "expiry should be ~1h ahead, got {delta:?}"
        );
    }

    /// 坏时长在解锁之前拒绝（不设 PERSONA_MASTER_PASSWORD：真走到解锁
    /// 会被 ScriptedUi 卡住/报别的错，报错含 invalid duration 即证明
    /// 参数闸先于密码提示）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_bad_duration_fails_before_prompt() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        let err = execute_with(
            create_args_with_ttl("bad", &[], &[], Some("1x")),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "{err}");
        assert!(
            token_rows(&config).await.is_empty(),
            "no row must be written"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_scopes_narrows_and_rejects_bad_input() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(
            create_args("scoped", &["work"], &["password", "totp"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].scope.item_types.len(), 2);
        assert_eq!(rows[0].scope.identities.len(), 1);

        // 未知身份：bail 且不留半成品
        let err = execute_with(
            create_args("x", &["ghost"], &[]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert_eq!(token_rows(&config).await.len(), 1);

        // 非法类型词汇
        let err = execute_with(
            create_args("y", &[], &["passkey"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unknown item type"), "{err}");
        assert_eq!(token_rows(&config).await.len(), 1);
    }

    /// `connect token list`：空列表分支 + active/revoked 与
    /// never-used/revoked-at 状态行的完整打印路径。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn list_tokens_renders_empty_and_populated_states() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let list_args = || ConnectArgs {
            command: ConnectCommand::Token {
                command: TokenCommand::List,
            },
        };

        // 空库：走 "(none)" 早退分支
        execute_with(list_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // 两个 token，吊销其一：覆盖 active/revoked 两种状态行
        execute_with(create_args("alpha", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(create_args("beta", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 2);
        execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke {
                        target: rows[0].fingerprint.clone(),
                    },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();

        execute_with(list_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn list_and_revoke_by_id_or_fingerprint() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(create_args("a", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(create_args("b", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // 指纹吊销（list 展示的就是指纹）
        let fp = token_rows(&config).await[0].fingerprint.clone();
        execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke { target: fp },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
        let rows = token_rows(&config).await;
        assert!(rows[0].revoked_at.is_some());
        assert!(rows[1].revoked_at.is_none());

        // UUID 吊销 + 幂等
        let id = rows[1].id;
        for _ in 0..2 {
            execute_with(
                ConnectArgs {
                    command: ConnectCommand::Token {
                        command: TokenCommand::Revoke {
                            target: id.to_string(),
                        },
                    },
                },
                &config,
                &ScriptedUi::new(),
            )
            .await
            .unwrap();
        }
        assert!(token_rows(&config).await[1].revoked_at.is_some());
        // 幂等重复（false）不重复记审计：指纹 1 次 + UUID 首次 1 次
        assert_eq!(audit_count(&config, "connect_token_revoked").await, 2);

        // 未知 target
        let err = execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke {
                        target: "nope".to_string(),
                    },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("no token with id or fingerprint"),
            "{err}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn token_commands_require_unlocked_vault() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        // 错误主密码 → 认证失败（SERVICE 侧门禁语义在 core/desktop 已覆盖）
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong");
        let err = execute_with(create_args("x", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(err.to_string().contains("Authentication failed"), "{err}");
        assert!(token_rows(&config).await.is_empty());
    }

    /// serve 编排的冒烟（TCP 传输）：serve_until 的信号注入缝使
    /// resolve → 解锁 → start → 打印 → stop 全路径进单测
    /// （health/router 行为由 connect-server crate 全量覆盖）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_pipeline_tcp_starts_prints_and_stops_on_signal() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        // 信号立即就绪：serve 编排全路径（resolve → 解锁 → start →
        // 打印 TCP 端点臂 → 收信号 → stop → 收尾打印）必须走完并正常返回。
        // health 冒烟不在此重复——connect-server lib 的 http_over_tcp
        // 测试已全量覆盖（含三防线），此处钉的是 serve 自身的编排。
        serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            None,
            None,
            std::future::ready(Ok(())),
        )
        .await
        .unwrap();
    }

    /// serve 编排的冒烟（unix 传输，serve_until 驱动）：health 应答作为
    /// 退出信号的前置条件——serve 必须真的把 listener 起来、打印 unix 端点臂、
    /// 收到信号后 stop 并移除 socket 文件，全路径单测执行。
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_pipeline_over_unix_socket_serves_health_then_cleans_up() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let socket = _dir.path().join("connect.sock");
        // 退出信号 = 首次 health 应答成功（listener 真起来了才允许退出）。
        let probe = async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // 结构上刻意「先睡后探 + 标志位退出」：sleep 无条件执行；成功用
            // fall-through 而非 return/break 跳出，块收尾花括号在每次成功
            // 迭代里都被执行（early return 会让它们成为永远填不上的覆盖洞）。
            let mut answered = false;
            for _ in 0..300 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                if let Ok(mut stream) = tokio::net::UnixStream::connect(&socket).await {
                    let _ = stream
                        .write_all(
                            b"GET /api/v1/connect/health HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    let mut buf = Vec::new();
                    let _ = stream.read_to_end(&mut buf).await;
                    let body = String::from_utf8_lossy(&buf);
                    if body.contains("\"ok\":true") && body.contains("persona-connect") {
                        answered = true;
                    }
                }
                if answered {
                    break;
                }
            }
            if !answered {
                anyhow::bail!("unix listener 未在 3s 内应答 health");
            }
            Ok(())
        };
        serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            Some(Some(socket.clone())),
            None,
            probe,
        )
        .await
        .unwrap();

        // 收尾：socket 文件随 stop 移除（轮询，不 sleep 猜时长）
        let mut gone = false;
        for _ in 0..100 {
            if !socket.exists() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone, "stop 后 socket 文件应移除: {}", socket.display());
    }

    /// SIGTERM 走优雅关停（systemd stop / kill 的入口）：`shutdown_signal()`
    /// 构造期即同步装好 OS handler（tokio `signal()` 语义），此后自发 SIGTERM
    /// 必被 tokio 接管并返回 Ok——而非默认行为直接杀死进程（那会在 unix 下
    /// 留陈旧 socket）。Ctrl-C 刻意保持惰性注册（密码提示的 ISIG 仍开，
    /// 提前接管会吞掉用户的取消键——见 shutdown_signal 文档）。
    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_signal_returns_ok_on_sigterm() {
        let fut = shutdown_signal().expect("signal() 构造期应完成注册");
        // 构造已完成注册，此刻的 SIGTERM 由 tokio 接管（不会杀死本测试进程）
        unsafe {
            libc::kill(std::process::id() as i32, libc::SIGTERM);
        }
        let result = fut.await;
        assert!(result.is_ok(), "SIGTERM 应触发关停信号: {result:?}");
    }

    /// 解锁失败不留半初始化状态：错误密码 → 先优雅关停（socket 文件真实
    /// 移除、连接被拒）再原样上抛——不存在「报错退出但 listener 还挂着」。
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_until_stops_listener_when_unlock_fails() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
        let socket = _dir.path().join("unlock-fail.sock");
        let result = serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            Some(Some(socket.clone())),
            None,
            std::future::ready(Ok(())),
        )
        .await;
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let err = result.expect_err("错误密码必须失败");
        assert!(
            err.to_string().contains("Authentication failed"),
            "应是认证失败而非其它: {err}"
        );
        assert!(!socket.exists(), "解锁失败后 socket 文件必须已移除");
        assert!(
            tokio::net::UnixStream::connect(&socket).await.is_err(),
            "解锁失败后连接必须被拒"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_passphrase_env_var_missing_is_a_hard_error() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        let err = execute_with(
            ConnectArgs {
                command: ConnectCommand::Serve {
                    port: 0,
                    unix_socket: None,
                    passphrase_env: Some("PERSONA_TEST_MISSING_VAR".to_string()),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("is not set (or blank)"), "{err}");
    }

    // -------------------------------------------------------------------
    // resolve_transport / default_socket_path
    // -------------------------------------------------------------------

    #[test]
    fn resolve_transport_defaults_to_loopback_tcp() {
        // matches! + guard：断言即判定，无 match+panic 的不可达覆盖死角。
        let t = resolve_transport(0, None).unwrap();
        assert!(
            matches!(t, persona_connect_server::ConnectTransport::Tcp { port: 0 }),
            "未给 --unix-socket 应得 TCP(0): {t:?}"
        );
        let t = resolve_transport(8737, None).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Tcp { port: 8737 }
            ),
            "--port 应得对应端口 TCP: {t:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_transport_unix_bare_uses_default_path_and_explicit_path_wins() {
        // 裸用 → 缺省路径（与 default_socket_path 一致）
        let t = resolve_transport(0, Some(None)).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Unix { ref path }
                    if *path == default_socket_path()
            ),
            "裸用应取缺省路径: {t:?}"
        );
        // 显式路径优先
        let explicit = std::path::PathBuf::from("/tmp/persona-test.sock");
        let t = resolve_transport(0, Some(Some(explicit.clone()))).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Unix { ref path }
                    if *path == explicit
            ),
            "显式路径应覆盖缺省: {t:?}"
        );
    }

    #[test]
    fn resolve_transport_rejects_port_plus_unix_socket() {
        // 两侧同时给是调用方旗标冲突：unix 无 TCP 端口，静默忽略任一侧
        // 都会让调用方对着错误端点排查——硬报错。
        let err = resolve_transport(8737, Some(None)).unwrap_err();
        assert!(err.to_string().contains("--unix-socket"), "{err}");
    }

    /// Windows：unix 传输在**解锁之前**即拒（fail-fast，不先要主密码）。
    /// 库侧 start_connect_server_with_transport 另有同语义兜底（见其测试）。
    #[cfg(not(unix))]
    #[test]
    fn resolve_transport_rejects_unix_before_unlock_on_windows() {
        let err = resolve_transport(0, Some(None)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not supported"), "应说明平台不支持: {msg}");
        assert!(msg.contains("TCP"), "应给出 TCP 替代指引: {msg}");
    }

    #[test]
    fn default_socket_path_is_stable_and_falls_back_under_persona_dir() {
        let path = default_socket_path();
        // display 预计算：多行 assert 的 message 参数行只在失败时执行，
        // 成功的测试填不上那个覆盖洞——先算好再单行断言。
        let shown = path.display().to_string();
        // 形态固定：*/persona/connect.sock 或 */.persona/connect.sock——
        // 消费者按文档定位，不随版本抖动。用 Path::ends_with 按**组件**比较：
        // 字符串斜杠后缀在 Windows（反斜杠）上必然误报（openclaw 实机抓到）。
        let stable_shape =
            path.ends_with("persona/connect.sock") || path.ends_with(".persona/connect.sock");
        assert!(stable_shape, "缺省路径形态不符: {shown}");
        if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
            // XDG_RUNTIME_DIR 是 unix 环境变量（此分支不会在 Windows 触发）；
            // 组件级前缀判断同上，避免分隔符绑定。
            let anchored = path.starts_with(std::path::Path::new("/"));
            assert!(anchored, "有 XDG_RUNTIME_DIR 时应在运行时目录: {shown}");
        }
    }

    /// 缺省路径内核三分支：runtime → home → cwd 兜底（default_socket_path
    /// 只是接线 dirs；分支逻辑在此钉死）。
    #[test]
    fn socket_path_from_prefers_runtime_then_home_then_cwd() {
        assert_eq!(
            socket_path_from(Some("/run/user/1000".into()), Some("/home/u".into())),
            std::path::PathBuf::from("/run/user/1000/persona/connect.sock")
        );
        assert_eq!(
            socket_path_from(None, Some("/home/u".into())),
            std::path::PathBuf::from("/home/u/.persona/connect.sock")
        );
        assert_eq!(
            socket_path_from(None, None),
            std::path::PathBuf::from("./.persona/connect.sock")
        );
    }
}
