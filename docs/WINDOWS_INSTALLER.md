# Windows installer and upgrade flow (NSIS)

> [English](WINDOWS_INSTALLER.md) | [中文](WINDOWS_INSTALLER.zh.md)

Status: landed 2026-09-25. Configuration lives in `desktop/src-tauri/tauri.conf.json`
(`bundle.windows.nsis`), the custom template in `desktop/src-tauri/nsis/installer.nsi`,
and the regression assertions in `desktop/src-tauri/src/packaging_tests.rs`.

## 1. Background: problems with the old upgrade logic

Tauri's official NSIS template actually ships a reinstall page (`PageReinstall`)
built in: when an older version is detected it makes the user choose between
"**install after uninstalling** / install without uninstalling", and in upgrade
scenarios "install after uninstalling" is **checked by default**. But under this
repo's old configuration it was effectively unusable/invisible, for four reasons:

| #   | Gap                                                                                                                                                          | Consequence                                                                                                                                                                                                                                                                                           |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `tauri.conf.json` had no `bundle.windows` section → `installMode` fell back to the default `currentUser`, and old-version detection only read HKCU (`SHCTX`) | If the old version was installed per-machine (HKLM, e.g. an MSI or perMachine NSIS), the **reinstall page never appeared at all**; the new version was installed side by side into `%LOCALAPPDATA%` — old files, old Start Menu/desktop shortcuts, and old uninstall registry entries all left behind |
| 2   | CI published both installers (NSIS per-user and MSI per-machine)                                                                                             | MSI upgrades go through `msiexec`/UpgradeCode and only recognize MSI's own older versions — **they never remove NSIS installations**; users switching between the two installer types ended up with mixed installs                                                                                    |
| 3   | NSIS silent install (`/S`) skips all custom pages                                                                                                            | The stock template under `/S` **never uninstalled the old version at all**: new files were overwritten in place, and old files that had been renamed or removed between versions stayed in the install directory forever                                                                              |
| 4   | During interactive upgrades the old version's uninstaller ran with the **full UI**                                                                           | Users had to click through the old version's entire uninstall wizard (including a "delete application data" checkbox) — not a "silent uninstall" — and it was easy to cancel midway                                                                                                                   |

## 2. The standard upgrade flow today

Four changes (relative to the `tauri-cli-v2.12.1` baseline template in the
`@tauri-apps/cli` 2.12.1 locked chain; every divergence is marked with a
`Persona 定制` comment):

1. **`installMode: "both"`**: first install shows a "all users on this machine /
   current user only" choice page (defaults to current user, no administrator
   needed); the choice is remembered and upgrades automatically reuse the old
   install's context — old-version detection now covers both HKCU and HKLM,
   closing gap 1.
2. **Upgrade path silently uninstalls the old version by default**: the reinstall
   page checks "install after uninstalling" (baseline behavior preserved), and
   the old version's uninstaller is passed `/S` — no UI and no confirmation page
   at all (gap 4).
3. **Fully silent install (`/S`) also uninstalls the old version first**:
   `EarlyChecks` (a Section that runs as usual in silent mode) calls
   `UninstallPreviousSilent`, with the same detection rules as the reinstall
   page: it first checks the NSIS uninstall key under SHCTX, then enumerates
   HKLM for WiX/MSI entries matching `DisplayName`+`Publisher` and uninstalls
   them with `msiexec /x {ProductCode} /quiet /norestart` (gap 3). If uninstalling
   fails the installer aborts (fail-closed — it refuses to install on top of
   leftovers from the old version).
4. **`!include "Win\RestartManager.nsh"`** (added 2026-10-04 with the 2.12.1
   baseline): CLI 2.12.x's `utils.nsh` mandates the Restart Manager macros for
   closing running processes, so the template must carry this include or
   makensis fails with `macro named RestartManager_StartSession not found`.

Behavior by entry point:

| Entry point                               | Behavior                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Double-click (interactive)                | Detect old version → reinstall page with "install after uninstalling" checked by default → old version **silently** uninstalled → new version installed                                                                                                                                                                                                                                                             |
| `/S` (silent/unattended)                  | Detect old version (NSIS or MSI) → **silent** uninstall → install; aborts with a non-zero exit code on failure                                                                                                                                                                                                                                                                                                      |
| `/P` (passive, progress bar only)         | Same as the interactive default path, pages advance automatically with default values                                                                                                                                                                                                                                                                                                                               |
| `/UPDATE` (internal to the Tauri updater) | Baseline semantics preserved: updates in place, no reinstall page, leaves uninstall keys and autostart entries untouched                                                                                                                                                                                                                                                                                            |
| `/PURGE` (uninstaller only)               | The uninstaller wipes all user data (vault + cache + CLI workspace) without a confirmation checkbox; no effect on the installer package; skipped under `/UPDATE`                                                                                                                                                                                                                                                    |
| Downgrade                                 | **No downgrade protection today**: `tauri.conf.json` does not set `plugins.updater.allowDowngrades` (the key is unconfigured, so tauri-cli takes the default `true`), and an older version can be downgraded onto. To enable protection you must set `allowDowngrades: false` explicitly in `tauri.conf.json` (a configuration decision, not changed on our own); `/S` mode still uninstalls the old version first. |

**MSI is no longer published** (since 2026-09-25 the `desktop-build.yml` Windows
matrix only builds `nsis`): shipping both installers for the same version is the
root cause of gap 2. The NSIS installer has a migration uninstall for old MSI
installs (silent `msiexec /x`); the reverse does not exist. If you genuinely need
an MSI (e.g. for GPO mass deployment), add `msi` back to the matrix — but you
own the risk of mixed installs.

## 3. Guarantees around data and configuration retention

- The Persona desktop database defaults to **`%APPDATA%\persona\persona.db`**
  (`default_db_path` in `commands.rs`: `dirs::data_dir()/persona`).
- The NSIS uninstaller's built-in "delete application data" checkbox removes
  `%APPDATA%\com.persona.desktop` and `%LOCALAPPDATA%\com.persona.desktop`
  (Tauri/WebView cache-type data) and **never touches the database directory**;
  it only runs when the user explicitly checks it during a manual uninstall. The
  upgrade path's silent uninstall (`/S`) has no UI, so that checkbox is always
  unchecked.
- OS keyring entries (biometrics/sync tokens, `token_store.rs`) are unrelated to
  the installer and are unaffected by upgrades and uninstalls.
- Bottom line: **upgrades (including `/S` unattended) do not lose the database or
  configuration**. To wipe all local data you must delete `%APPDATA%\persona`
  manually after uninstalling.
- For the cross-platform policy (Linux/macOS/CLI uninstalls likewise never delete
  data, plus an explicit purge step) see [UNINSTALL](./UNINSTALL.md);
  `packaging_tests.rs`'s `nsis_uninstall_never_targets_vault_data_dir` pins
  "the vault directory never appears in uninstall delete instructions" as a
  regression assertion (2026-09-28).

## 4. Upgrade matrix

| Old install             | New  | Result                                                                                                                            |
| ----------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------- |
| NSIS per-user (HKCU)    | NSIS | Reinstall page checks uninstall by default → silent uninstall of the old version (including old shortcuts/registry) → install new |
| NSIS per-machine (HKLM) | NSIS | `installMode=both` reuses the old context, detects the HKLM key → same as above (administrator required)                          |
| MSI (HKLM)              | NSIS | Reinstall page forces the WiX migration uninstall (interactive), `/S` goes through `msiexec /x /quiet`                            |
| None                    | NSIS | Fresh install (the per-user/per-machine choice page appears)                                                                      |
| NSIS                    | MSI  | **Not supported** (MSI never removes NSIS installs, leaving leftovers) — MSI publication has stopped                              |

## 5. Windows machine acceptance checklist

This repo is developed on Linux, where NSIS cannot be compiled and verified
locally; run the checklist below when you have a Windows environment (it covers
the behavior layer above what `packaging_tests.rs` can only cover at the
configuration layer):

1. `pnpm install --frozen-lockfile --filter persona-desktop... && pnpm exec tauri build --bundles nsis` succeeds and produces `-setup.exe`.
2. Fresh install ×2: choose "current user only" and "all users" respectively,
   confirming the install directory (`%LOCALAPPDATA%\Persona` /
   `Program Files\Persona`) and the uninstall key location match the choice.
3. Upgrade: install the old version → run the new installer → confirm
   ① the reinstall page appears with "install after uninstalling" **checked by
   default**; ② the old version's uninstall runs entirely without UI; ③
   afterwards only **one** product uninstall key remains in HKCU/HKLM;
   ④ `%APPDATA%\persona\persona.db` is preserved as-is and the old database can
   be unlocked directly.
4. Silent upgrade: `persona-setup.exe /S` (check `%ERRORLEVEL%`=0 in cmd); the
   result matches ③④ above.
5. MSI migration: install the old MSI → run the new NSIS `/S` → the old MSI
   entry disappears from HKLM.
6. Manual uninstall ×2: leave "delete application data" unchecked and checked,
   confirming `%APPDATA%\persona` survives in both cases (checking it only
   clears the `com.persona.desktop` cache directories).
7. Downgrade: "do not uninstall" is greyed out in interactive mode; `/S` mode
   still uninstalls the old version first.

## 6. Template maintenance

`nsis/installer.nsi` is based on the
[`tauri-cli-v2.12.1`](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.12.1/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi)
baseline (`@tauri-apps/cli ^2.12.1` in `desktop/package.json`, the lock pinning
`tauri` to 2.12.1). When upgrading the CLI: download the new baseline template →
replay the four `Persona 定制` changes (see the header comment, including the
`!include "Win\RestartManager.nsh"` that became mandatory in 2.12.x — without it
makensis fails immediately with `RestartManager_StartSession not found`) →
update the baseline tag in the header comment → run
`cargo test -p persona-desktop packaging` (or the full test suite) to confirm
the assertions still pass.
