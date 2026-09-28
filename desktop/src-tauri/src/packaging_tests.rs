//! 打包配置回归测试（tauri.conf.json + 自定义 NSIS 模板）。
//!
//! Windows 安装器的升级语义（默认静默卸载旧版、保留用户数据）落在
//! 配置与模板文件里，Linux 本机无法编译 NSIS 验证 —— 至少用这些断言
//! 防止配置/模板被悄悄回退。完整说明与 Windows 机器上的验收清单见
//! docs/WINDOWS_INSTALLER.md。

use serde_json::Value;

fn manifest_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
}

#[test]
fn nsis_bundle_config_pins_install_mode_and_custom_template() {
    let conf: Value = serde_json::from_str(&manifest_file("tauri.conf.json")).unwrap();
    let nsis = conf["bundle"]["windows"]["nsis"]
        .as_object()
        .expect("bundle.windows.nsis must stay configured (docs/WINDOWS_INSTALLER.md)");
    // installMode=both：重装检测同时覆盖历史 per-user / per-machine 安装
    assert_eq!(nsis["installMode"], "both", "installMode must stay 'both'");
    // 自定义模板路径（相对 tauri.conf.json 所在目录）必须存在
    assert_eq!(
        nsis["template"], "nsis/installer.nsi",
        "custom installer template must stay wired"
    );
    assert!(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("nsis/installer.nsi")
            .exists(),
        "nsis/installer.nsi is missing next to tauri.conf.json"
    );
}

#[test]
fn custom_nsis_template_keeps_persona_upgrade_diffs() {
    let nsi = manifest_file("nsis/installer.nsi");

    // 定制 1)：升级路径默认勾选"卸载后安装"，且旧卸载器加 /S 静默执行
    assert!(
        nsi.contains("Persona 定制 1)"),
        "silent-uninstall diff marker missing from installer.nsi"
    );
    assert!(
        nsi.contains("StrCpy $R1 \"$R1 /S\""),
        "old uninstaller must be invoked with /S (silent, data-preserving)"
    );
    // 重装页第一个单选钮（卸载后安装）默认选中 —— 基线模板行为，防误删
    assert!(
        nsi.contains("SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0"),
        "reinstall page must keep 'uninstall before installing' as default-checked"
    );

    // 定制 2)：完全静默（/S）安装同样先卸载旧版
    assert!(
        nsi.contains("Persona 定制 2)"),
        "silent-mode diff marker missing from installer.nsi"
    );
    assert!(nsi.contains("Call UninstallPreviousSilent"));
    assert!(nsi.contains("Function UninstallPreviousSilent"));

    // 基线模板的关键锚点仍在（升级 @tauri-apps/cli 后重放差异时的对照）
    assert!(nsi.contains("!define INSTALLMODE \"{{install_mode}}\""));
    assert!(nsi.contains(
        "!define UNINSTKEY \"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${PRODUCTNAME}\""
    ));
    // 数据安全：仅当用户勾选"删除应用数据"或 /PURGE 显式清除且非更新模式才清 AppData
    assert!(nsi.contains("${If} $DeleteAppDataCheckboxState = 1${OrIf} $PurgeMode = 1"));
    // /PURGE 静默彻底清除参数必须被解析
    assert!(
        nsi.contains("${GetOptions} $CMDLINE \"/PURGE\" $PurgeMode"),
        "silent purge flag must be supported"
    );
    // 且解析必须位于 /UPDATE 块之外（嵌套进去会让单独 /PURGE 静默失效）
    let update_strcpy = nsi
        .find("StrCpy $UpdateMode 1")
        .expect("update flag must be parsed");
    let after_update = &nsi[update_strcpy..];
    let purge_pos = after_update
        .find("\"/PURGE\"")
        .expect("purge flag must be parsed");
    assert!(
        after_update[..purge_pos].contains("${EndIf}"),
        "/PURGE must be parsed outside the /UPDATE block"
    );
}

/// 卸载不删 vault 数据（docs/UNINSTALL.md 的承诺）：
/// NSIS 模板里所有递归删除（`RmDir /r`）必须只指向 `${BUNDLEID}`
/// 缓存目录（WebView 缓存 + 日志），vault 所在的 `%APPDATA%\persona`
/// （`default_db_path`，与 BUNDLEID 无关）绝不允许出现在任何删除指令
/// 里。升级路径的静默卸载（/S）没有确认页 => 勾选框恒未勾 => 连缓存
/// 目录都不会被清；vault 目录则任何路径都删不到。
#[test]
fn nsis_uninstall_never_targets_vault_data_dir() {
    let nsi = manifest_file("nsis/installer.nsi");

    let recursive_rmdirs: Vec<&str> = nsi
        .lines()
        .filter(|line| {
            // 精确匹配递归标志 `/r `（`/REBOOTOK` 也以 /R 开头，但它只
            // 是重启时删除、目标仍是 $INSTDIR 安装残留，不在本断言范围）
            line.trim_start()
                .to_ascii_lowercase()
                .starts_with("rmdir /r ")
        })
        .collect();
    assert!(
        !recursive_rmdirs.is_empty(),
        "expected the template to still clean ${{BUNDLEID}} cache dirs on explicit opt-in; \
         if the uninstall section was rewritten, re-audit docs/UNINSTALL.md promises"
    );
    for line in &recursive_rmdirs {
        assert!(
            line.contains("${BUNDLEID}"),
            "recursive delete outside the cache dirs is forbidden: {line:?}"
        );
    }

    // vault 路径（`dirs::data_dir()/persona`）不得成为任何删除/移除指令
    // 的目标；删除指令 = 行首 RMDir/RmDir 或 Delete（忽略注释行）。
    for line in nsi.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(';') {
            continue; // 注释里提及 vault 路径是允许的（说明文档）
        }
        let upper = trimmed.to_ascii_uppercase();
        let is_delete_cmd = upper.starts_with("RMDIR")
            || upper.starts_with("DELETE \"")
            || upper.starts_with("DELETE $");
        if is_delete_cmd {
            assert!(
                !trimmed.contains("\\persona\""),
                "vault data dir must never be a deletion target: {line:?}"
            );
        }
    }
}
