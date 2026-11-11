use super::*;

// ------------------------------------------------------------------
// execute_with: confirmation gates and identity selection.
// ------------------------------------------------------------------

#[tokio::test]
async fn execute_with_json_export_respects_confirm_gate() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    let out = dir.path().join("out.json");

    // Declining the confirmation writes nothing.
    let ui = ScriptedUi::new().confirm(false);
    execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
        .await
        .expect("cancelling returns success");
    assert!(ui.exhausted());
    assert!(!out.exists(), "cancelled export must not write the file");

    // Accepting writes the file.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(with_output(args(&["alice"], "json"), &out), &config, &ui)
        .await
        .expect("confirmed export succeeds");
    assert!(ui.exhausted());
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("alice"));
}

#[tokio::test]
async fn execute_with_sensitive_gate_can_abort_or_proceed() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    let out = dir.path().join("sensitive.json");

    // The second (sensitive) confirmation can still abort.
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    let ui = ScriptedUi::new().confirm(true).confirm(false);
    execute_with(a, &config, &ui)
        .await
        .expect("aborting at the sensitive gate returns success");
    assert!(ui.exhausted());
    assert!(!out.exists(), "aborted sensitive export writes nothing");

    // Confirming both gates performs the export.
    let mut a = with_output(args(&["alice"], "json"), &out);
    a.include_sensitive = true;
    let ui = ScriptedUi::new().confirm(true).confirm(true);
    execute_with(a, &config, &ui)
        .await
        .expect("double-confirmed sensitive export succeeds");
    assert!(ui.exhausted());
    assert!(out.exists());
}

#[tokio::test]
async fn execute_with_all_identities_and_interactive_selection() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice", "bob", "carol"]).await;
    let out = dir.path().join("all.json");

    // Empty names means "every identity"; no prompts before the confirm.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(with_output(args(&[], "json"), &out), &config, &ui)
        .await
        .expect("exporting every identity succeeds");
    assert!(ui.exhausted());
    let content = std::fs::read_to_string(&out).unwrap();
    for name in ["alice", "bob", "carol"] {
        assert!(content.contains(name), "missing {name}");
    }

    // Interactive mode maps multi_select indices back to names.
    let out_selected = dir.path().join("selected.json");
    let ui = ScriptedUi::new().multi_select(&[0, 2]).confirm(true);
    let mut a = args(&[], "json");
    a.interactive = true;
    execute_with(with_output(a, &out_selected), &config, &ui)
        .await
        .expect("interactive selection exports the picked identities");
    assert!(ui.exhausted());
    let content = std::fs::read_to_string(&out_selected).unwrap();
    assert!(content.contains("alice"));
    assert!(content.contains("carol"));
    assert!(!content.contains("bob"), "unpicked identity stays out");

    // Selecting nothing reports there is nothing to export.
    let out_empty = dir.path().join("empty.json");
    let ui = ScriptedUi::new().multi_select(&[]);
    let mut a = args(&[], "json");
    a.interactive = true;
    execute_with(with_output(a, &out_empty), &config, &ui)
        .await
        .expect("empty selection returns success");
    assert!(ui.exhausted());
    assert!(!out_empty.exists());
}

#[tokio::test]
async fn execute_with_unknown_identity_fails_before_any_prompt() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;

    let ui = ScriptedUi::new();
    let err = execute_with(
        with_output(args(&["ghost"], "json"), &dir.path().join("g.json")),
        &config,
        &ui,
    )
    .await
    .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
    assert!(ui.exhausted(), "validation fails before any prompt");
}

#[tokio::test]
async fn execute_wrapper_bails_when_no_identities_exist() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);

    // The interactive selection path bails before any prompt when the
    // workspace has no identities at all, so the TerminalUi-backed entry
    // point is safe to exercise here.
    let mut a = args(&[], "json");
    a.interactive = true;
    let err = execute(a, &config)
        .await
        .expect_err("empty workspace must fail");
    assert!(err.to_string().contains("No identities found to export"));
}
