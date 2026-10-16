# Uninstall and Data Retention (Uninstall Keeps Data; Reinstall Picks Up Where You Left Off)

> [English](UNINSTALL.md) | [中文](UNINSTALL.zh.md)

Status: verified and closed 2026-09-28. The promise in one sentence: **uninstalling or
upgrading on any platform never deletes vault data; after reinstalling, unlock with the
original master password and pick up right where you left off**. A complete wipe of the data is
always an explicit user action (see the "Complete Purge" section below) — the uninstaller will
never do it for you.

## 1. Where All the Data Lives

| Content                | Location                                                                                                                                              | Written by                                                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **vault database**     | Windows `%APPDATA%\persona\persona.db`; Linux `~/.local/share/persona/`; macOS `~/Library/Application Support/persona/`                               | Desktop `default_db_path` (`dirs::data_dir()/persona`)                  |
| **CLI workspace**      | `~/.persona/` (`identities.db`, `bridge/`, SSH agent state)                                                                                           | CLI (overridable via `PERSONA_DB_PATH` and other environment variables) |
| **OS keyring entries** | system credential manager (Windows Credential Manager / Secret Service / Keychain)                                                                    | biometric unlock, sync tokens (`token_store.rs`)                        |
| **Cache and logs**     | `<bundle directory>`: Windows `%APPDATA%\com.persona.desktop` and `%LOCALAPPDATA%\com.persona.desktop`; corresponding XDG/Bundle paths on Linux/macOS | WebView cache, run logs — **contains no secrets**                       |

The vault database and the cache directory are two entirely unrelated paths: the
database lives in `persona/`, the cache in `com.persona.desktop/`. Even if the
uninstaller clears the cache, it cannot touch the database.

## 2. Uninstall Behavior Per Platform (Everything Kept by Default)

| Platform / installer | Uninstall action                                                                                      | vault database | CLI workspace | keyring | Cache / logs                                                                                                                                                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------- | -------------- | ------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows NSIS         | "Apps & features" uninstall (confirm page has a "delete app data" checkbox, **unchecked by default**) | **kept**       | kept          | kept    | kept by default; `com.persona.desktop` is cleared only when **explicitly checked**                                                                                           |
| Windows upgrade      | the new installer silently uninstalls the old one automatically (`/S`, no UI)                         | **kept**       | kept          | kept    | kept (the silent path has no checkbox)                                                                                                                                       |
| Linux deb / rpm      | `apt remove` / `dnf remove`                                                                           | **kept**       | kept          | kept    | kept (the package contains no maintainer-removal scripts at all — `postrm` does not exist; the tauri bundler only copies user-supplied scripts, and this repo supplies none) |
| Linux AppImage       | delete the .AppImage file                                                                             | **kept**       | kept          | kept    | kept                                                                                                                                                                         |
| macOS dmg            | drag into the Trash                                                                                   | **kept**       | kept          | kept    | kept                                                                                                                                                                         |
| CLI (cargo/binary)   | delete the binary                                                                                     | kept           | **kept**      | kept    | kept                                                                                                                                                                         |

Windows behavior is guaranteed by `desktop/src-tauri/nsis/installer.nsi` and pinned
by regression assertions (`desktop/src-tauri/src/packaging_tests.rs`):

- upgrade / silent uninstall appends `/S` to the previous uninstaller — the confirm
  page never appears, and "delete app data" stays unchecked by default
  (`nsis_bundle_config_pins_install_mode_and_custom_template` and
  `custom_nsis_template_keeps_persona_upgrade_diffs`);
- `nsis_uninstall_never_targets_vault_data_dir`: **every** recursive-delete
  instruction in the template (`RmDir /r`) must point only at the `${BUNDLEID}`
  cache directory, and no delete instruction may target the vault directory
  (`\persona"`) — the test goes red if the template is changed.

## 3. Reinstall Continuity

After reinstalling or upgrading, no data migration is needed: the installer neither
creates nor deletes the vault; first launch still resolves `default_db_path`, and
unlocking with the original master password restores every item, identity, and
setting. Linux/macOS behave the same way (see the paths in the table above).
**Uninstall → reinstall = lossless**; data is only lost if you go through the
"Complete Purge" in the next section.

## 4. Complete Purge (Explicit Purge)

If you want a truly clean slate, there are two ways:

### Option 1: Manual Commands (Works on All Platforms)

Run these per platform (**confirm you have a backup before deleting**; once the
vault is deleted it cannot be recovered):

**Windows (PowerShell)**

```powershell
Remove-Item -Recurse -Force "$env:APPDATA\persona"          # vault database
Remove-Item -Recurse -Force "$env:APPDATA\com.persona.desktop"    # cache
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\com.persona.desktop" # cache/logs
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\.persona"  # CLI workspace
```

**Linux**

```bash
rm -rf ~/.local/share/persona   # vault database
rm -rf ~/.persona               # CLI workspace + SSH agent state
```

**macOS**

```bash
rm -rf "$HOME/Library/Application Support/persona"  # vault database
rm -rf ~/.persona                                   # CLI workspace
```

### Option 2: NSIS Uninstaller /PURGE Flag (Windows Only)

Run the **uninstaller** (`uninstall.exe` in the install directory — not the
installer) with the `/PURGE` flag, and it will wipe all user data (vault + cache +
CLI workspace) without the "delete app data" checkbox needing to be checked:

```powershell
# The uninstaller lives in the install directory (per-user default %LOCALAPPDATA%\Persona\uninstall.exe)
# Interactive uninstall + complete purge
& "$env:LOCALAPPDATA\Persona\uninstall.exe" /PURGE
# Silent uninstall + complete purge
& "$env:LOCALAPPDATA\Persona\uninstall.exe" /S /PURGE
```

`/PURGE` and `/S` can be combined; in upgrade mode (`/UPDATE`) the data purge is
skipped (updates never delete data — `/PURGE` only takes effect on non-upgrade
uninstalls).

## 5. Change Inventory Checklist

Files involved in "uninstall keeps data": `desktop/src-tauri/nsis/installer.nsi`
(custom silent uninstall for upgrades), `desktop/src-tauri/src/packaging_tests.rs`
(regression assertions), this document, `docs/WINDOWS_INSTALLER.md` §3 (Windows
details), README (links).
