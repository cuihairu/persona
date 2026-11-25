//! Packaging configuration regression tests (tauri.conf.json + the custom
//! NSIS template).
//!
//! The Windows installer's upgrade semantics (default silent uninstall of the
//! old version, user data preserved) live in the config and template files,
//! and NSIS cannot be compiled to verify them on a Linux machine — these
//! assertions at least prevent the config/template from quietly regressing.
//! For the full explanation and the acceptance checklist on a Windows
//! machine, see docs/WINDOWS_INSTALLER.md.

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
    // installMode=both: reinstall detection covers both legacy per-user and
    // per-machine installs
    assert_eq!(nsis["installMode"], "both", "installMode must stay 'both'");
    // The custom template path (relative to tauri.conf.json's directory) must exist
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

    // Customization 1): the upgrade path defaults to "uninstall before
    // installing" checked, and the old uninstaller runs /S silently
    assert!(
        nsi.contains("Persona 定制 1)"),
        "silent-uninstall diff marker missing from installer.nsi"
    );
    assert!(
        nsi.contains("StrCpy $R1 \"$R1 /S\""),
        "old uninstaller must be invoked with /S (silent, data-preserving)"
    );
    // The reinstall page's first radio button (uninstall before installing)
    // defaults to checked — baseline template behavior, guarded against
    // accidental deletion
    assert!(
        nsi.contains("SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0"),
        "reinstall page must keep 'uninstall before installing' as default-checked"
    );

    // Customization 2): a fully silent (/S) install also uninstalls the old
    // version first
    assert!(
        nsi.contains("Persona 定制 2)"),
        "silent-mode diff marker missing from installer.nsi"
    );
    assert!(nsi.contains("Call UninstallPreviousSilent"));
    assert!(nsi.contains("Function UninstallPreviousSilent"));

    // The baseline template's key anchors are still there (the reference used
    // when replaying the diffs after upgrading @tauri-apps/cli)
    assert!(nsi.contains("!define INSTALLMODE \"{{install_mode}}\""));
    assert!(nsi.contains(
        "!define UNINSTKEY \"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${PRODUCTNAME}\""
    ));
    // Data safety: AppData is cleared only when the user checks "delete app
    // data", or /PURGE explicitly requests it, and it is not an update mode.
    // Each of LogicLib's If/OrIf/AndIf must sit on its own line — inlining
    // `${OrIf}` on the same line makes makensis abort on a macro argument
    // count mismatch (the 2026-09-28 daily build's Windows bundle failed
    // installer.nsi in practice), so the line breaks are pinned along with
    // it.
    assert!(
        nsi.contains("${If} $DeleteAppDataCheckboxState = 1\n  ${OrIf} $PurgeMode = 1"),
        "OrIf must be on its own line (LogicLib multi-line condition)"
    );
    // The /PURGE silent full-purge flag must be parsed
    assert!(
        nsi.contains("${GetOptions} $CMDLINE \"/PURGE\" $PurgeMode"),
        "silent purge flag must be supported"
    );
    // And the parse must sit outside the /UPDATE block (nesting it there
    // would silently break a standalone /PURGE)
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

/// The utils.nsh contract for CLI >= 2.12 (proven on the 2026-10-03 daily
/// build's Windows leg): tauri-bundler force-writes the CLI's embedded
/// utils.nsh during staging (not controlled by the custom template), and its
/// CheckIfAppIsRunning switches to Restart Manager macros — so this template
/// must include `Win\RestartManager.nsh`, and both call sites must pass the
/// full binary path (the new macros register files by path). Without the
/// include, makensis reports "macro named RestartManager_StartSession not
/// found" straight away (run 37155098351). Reproduced locally with the real
/// 2.12.1 utils.nsh + nsis_tauri_utils.dll against makensis: old template
/// fails / new template compiles (2026-10-04). This contract needs re-checking
/// when the CLI baseline is upgraded.
#[test]
fn custom_nsis_template_satisfies_cli_utils_nsh_contract() {
    let nsi = manifest_file("nsis/installer.nsi");
    assert!(
        nsi.contains("!include \"Win\\RestartManager.nsh\""),
        "CLI 2.12.x utils.nsh uses RestartManager macros; \
         template must include Win\\RestartManager.nsh"
    );
    assert_eq!(
        nsi.matches(
            "!insertmacro CheckIfAppIsRunning \"$INSTDIR\\${MAINBINARYNAME}.exe\" \"${PRODUCTNAME}\""
        )
        .count(),
        2,
        "both CheckIfAppIsRunning call sites must pass the full binary path (2.12 macro signature)"
    );
}

/// Uninstall never deletes vault data (the promise in docs/UNINSTALL.md):
/// every recursive deletion (`RmDir /r`) in the NSIS template must target
/// only the `${BUNDLEID}` cache directory (WebView cache + logs), and the
/// `%APPDATA%\persona` directory holding the vault (`default_db_path`,
/// unrelated to BUNDLEID) must never appear in any deletion command. The
/// upgrade path's silent uninstall (/S) has no confirmation page => the
/// checkbox is never ticked => not even the cache directory gets cleared;
/// the vault directory is unreachable from every path.
#[test]
fn nsis_uninstall_never_targets_vault_data_dir() {
    let nsi = manifest_file("nsis/installer.nsi");

    let recursive_rmdirs: Vec<&str> = nsi
        .lines()
        .filter(|line| {
            // Match the recursive flag `/r ` exactly (`/REBOOTOK` also starts
            // with /R, but it only deletes on reboot, and its target is still
            // $INSTDIR install leftovers, outside this assertion's scope)
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

    // The vault path (`dirs::data_dir()/persona`) must not become the target
    // of any delete/remove command; deletion command = RMDir/RmDir at line
    // start or Delete (comment lines ignored).
    for line in nsi.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(';') {
            continue; // Mentioning the vault path in a comment is allowed (documentation)
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
