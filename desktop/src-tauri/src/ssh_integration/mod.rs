//! 「SSH 走 persona agent」的 ~/.ssh/config 集成。
//!
//! 原理：OpenSSH 8.3+ 的 `IdentityAgent` 指令可为 host 指定 agent socket，
//! 等效于对单个 host 导出的 `SSH_AUTH_SOCK`。桌面壳把 agent 固定监听在
//! 稳定路径（见 [`agent_stable_socket`]），本模块把该路径写进 `~/.ssh/config`
//! 的 `# persona managed begin/end` 锚点注释块——只动块内，用户其余配置
//! 一律不碰；停用即整块移除。
//!
//! 作用域：OpenSSH 按文件顺序取「首个匹配该 host 的值」，而追加到 EOF 的
//! 配置行会落入用户**最后一个 Host/Match 块**的作用域（若用户 config 以
//! `Host github.com` 结尾，其他 host 根本拿不到 persona agent）。因此块内
//! 带一行 `Host *`：EOF 处的全域匹配对所有 host 生效，且用户写在文件更前
//! 面的 host 级 `IdentityAgent` 按 first-wins 语义原样优先。

use std::path::Path;

use serde::Serialize;

mod config_block;
mod config_scan;
#[cfg(test)]
mod tests;

pub use config_block::{
    agent_stable_socket, has_manual_persona_entry, identity_agent_value,
    managed_block_identity_agent, remove_managed_block, ssh_config_path, upsert_managed_block,
    write_config_atomic,
};
pub use config_scan::probe_ssh_version;
use config_scan::{collect_agent_entries, socket_probe};

/// 锚点注释：块识别的唯一标记，改动会破坏老配置的停用路径
pub const BLOCK_BEGIN: &str = "# persona managed begin";
pub const BLOCK_END: &str = "# persona managed end";

/// 集成状态三态由前端按 `enabled`/`anomaly` 组合渲染
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshIntegrationStatus {
    /// 锚点块存在且 IdentityAgent 指向当前稳定 socket
    pub enabled: bool,
    /// 锚点块存在但指向别处（旧路径/手改过）——重新启用即可修复
    pub anomaly: Option<String>,
    /// 锚点块外用户手写的 persona IdentityAgent（提示但不自动动它）
    pub manual_entry: bool,
    pub config_path: String,
    /// agent 稳定 socket（写入值/比对基准）
    pub socket_path: String,
    /// 锚点块当前的 IdentityAgent 值（未启用时 None）
    pub identity_agent: Option<String>,
    /// OpenSSH < 8.3 不支持 IdentityAgent（version 探测失败时不填）
    pub ssh_version: Option<String>,
    /// config 文件在盘上（不存在不算错误：首次启用会创建）
    pub config_exists: bool,
    /// 读失败原因（权限/IO）——如实显示，绝不静默吞（启用路径据此拒绝写）
    pub read_error: Option<String>,
}

/// 一条 agent 相关配置行（Include 展开后的真实来源）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigEntry {
    /// 来源文件（Include 展开前的主 config 或被 Include 的文件）
    pub file: String,
    /// 1 起的行号
    pub line: usize,
    /// 所处作用域：空串 = 顶层（对所有 host 生效）；否则 Host/Match 行原文
    pub scope: String,
    /// 关键字（原样大小写，比较时用小写）
    pub keyword: String,
    /// 值（去引号）
    pub value: String,
}

/// `~/.ssh/config`（含 Include 展开）的 agent 相关面分析。
/// 只读；任何失败都落到字段里如实显示，不让前端猜。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigAgentAnalysis {
    pub config_path: String,
    pub config_exists: bool,
    pub readable: bool,
    /// 读失败原因（权限/IO，如 config 是目录/权限不足）
    pub read_error: Option<String>,
    /// 非致命解析警告（Include 缺文件/循环/超深度/glob 无匹配）
    pub warnings: Vec<String>,
    /// agent 相关条目（含 Include 展开；persona 锚点块内不计——块状态单独看）
    pub entries: Vec<SshConfigEntry>,
    /// ForwardAgent 条目集合（on/off 值原样，作用域各自标明）
    pub forward_agent_entries: Vec<SshConfigEntry>,
    /// 生效 IdentityAgent：ssh 语义「首个匹配值」的顶层级近似——第一个
    /// 顶层（无 Host/Match 限定）条目优先；无用户全局条目时取 persona
    /// 锚点块值（Host * 对所有连接生效，块在 EOF 被更早条目压过）；两者
    /// 皆无时 None（对不同 host 结果不同，不妄断）。
    pub identity_agent_effective: Option<String>,
    /// 环境 SSH_AUTH_SOCK（无则 None）
    pub ssh_auth_sock: Option<String>,
    /// ssh 实际会用到的 socket：effective IdentityAgent 优先，其次环境
    pub effective_socket: Option<String>,
    /// effective_socket 的 Unix socket 连通探测（None = 平台不支持/无 socket）
    pub socket_alive: Option<bool>,
    /// persona agent 稳定 socket 是否有进程在听（= agent 运行中）
    pub persona_socket_alive: bool,
}

/// 读 config（含 Include 展开）并分析 agent 相关面。任何失败落字段，
/// 绝不 panic、绝不静默吞。
pub fn analyze_config(config_path: &Path, ssh_auth_sock: Option<String>) -> SshConfigAgentAnalysis {
    let exists = config_path.exists();
    let mut read_error = None;
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    // 锚点块值参与生效判定：块追加在文件 EOF，用户更早的全局条目按
    // 「先出现先生效」压过它；没有用户全局条目时块值就是 ssh 实际用的值
    let mut managed_block_value = None;
    if exists {
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                managed_block_value = managed_block_identity_agent(&content);
                // 主文件里 persona 锚点块的行号区间（块内条目不计）
                let skip_span = {
                    let lines: Vec<&str> = content.lines().collect();
                    let begin = lines.iter().position(|l| l.trim() == BLOCK_BEGIN);
                    let end = lines.iter().position(|l| l.trim() == BLOCK_END);
                    begin.zip(end).filter(|(b, e)| e >= b)
                };
                let mut visited = std::collections::HashSet::new();
                collect_agent_entries(
                    config_path,
                    0,
                    true,
                    skip_span,
                    &mut visited,
                    &mut warnings,
                    &mut entries,
                );
            }
            Err(e) => read_error = Some(e.to_string()),
        }
    }

    // ssh 语义「首个匹配值」的顶层级近似：第一个顶层（全局作用域）
    // IdentityAgent；只有 host 级条目时不妄断（不同 host 结果不同），
    // 此时退锚点块值（Host * 对所有连接生效）。
    let identity_agent_effective = entries
        .iter()
        .find(|e| e.keyword.eq_ignore_ascii_case("identityagent") && e.scope.is_empty())
        .map(|e| e.value.clone())
        .or(managed_block_value);
    let forward_agent_entries = entries
        .iter()
        .filter(|e| e.keyword.eq_ignore_ascii_case("forwardagent"))
        .cloned()
        .collect();
    let effective_socket = identity_agent_effective
        .clone()
        .or_else(|| ssh_auth_sock.clone());
    let socket_alive = effective_socket
        .as_deref()
        .map(|s| socket_probe(Path::new(s)));
    let persona_socket_alive = socket_probe(&agent_stable_socket());

    SshConfigAgentAnalysis {
        config_path: config_path.display().to_string(),
        config_exists: exists,
        readable: read_error.is_none(),
        read_error,
        warnings,
        entries,
        forward_agent_entries,
        identity_agent_effective,
        ssh_auth_sock,
        effective_socket,
        socket_alive,
        persona_socket_alive,
    }
}
