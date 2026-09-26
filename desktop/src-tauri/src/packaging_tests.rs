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
    // 数据安全：仅当用户勾选"删除应用数据"且非更新模式才清 AppData
    assert!(nsi.contains("${If} $DeleteAppDataCheckboxState = 1"));
}
