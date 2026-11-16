use super::*;

use std::path::Path;

#[test]
fn summary_lists_five_identities_then_folds_the_rest() {
    let mut data = ImportData {
        version: "1.0".to_string(),
        created: "2024-01-01".to_string(),
        identities: Vec::new(),
    };
    for i in 0..7 {
        data.identities.push(ImportIdentity {
            name: format!("user{i}"),
            identity_type: "personal".to_string(),
            description: String::new(),
            email: None,
            phone: None,
            tags: Vec::new(),
        });
    }

    // Dry-run and backup flags toggle their summary lines; more than five
    // identities fold into "... and N more".
    let mut summary_args = args(Path::new("/tmp/whatever.json"), true);
    summary_args.dry_run = true;
    summary_args.backup = true;
    show_import_summary(&data, &summary_args).unwrap();

    // Exactly five identities produce no fold line.
    data.identities.truncate(5);
    summary_args.dry_run = false;
    show_import_summary(&data, &summary_args).unwrap();
}
