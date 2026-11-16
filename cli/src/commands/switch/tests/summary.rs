use super::{config_for, ensure_workspace_row, seeded_db, switch_args};
use crate::commands::switch::execute;
use crate::commands::switch::flow::execute_with;
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::storage::IdentityRepository;
use persona_core::Repository;
use tempfile::TempDir;

#[tokio::test]
async fn switch_summary_renders_contact_details_and_tags() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["rich", "plain"]).await;
    ensure_workspace_row(&db, &config).await;

    // Give the identity email/phone/tags so every summary section prints.
    {
        let repo = IdentityRepository::new(db.clone());
        let mut rich = repo
            .find_by_name("rich")
            .await
            .unwrap()
            .expect("rich exists");
        rich.email = Some("rich@example.com".to_string());
        rich.phone = Some("+49123456789".to_string());
        rich.tags = vec!["ops".to_string(), "oncall".to_string()];
        rich.description = Some("the rich one".to_string());
        repo.update(&rich).await.unwrap();
    }

    execute(switch_args(Some("rich"), true), &config)
        .await
        .expect("switch to a fully-populated identity succeeds");

    // Interactive selection of the other identity renders the summary
    // for it afterwards. The menu is name-ordered: "plain" sorts first.
    let ui = ScriptedUi::new().select(0).confirm(true);
    execute_with(switch_args(None, false), &config, &ui)
        .await
        .expect("interactive switch to plain succeeds");
    assert!(ui.exhausted());
}
