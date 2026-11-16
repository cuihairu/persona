use super::*;

#[test]
fn single_field_edits_apply_and_clear_on_empty() {
    let mut identity = sample_identity();
    let ui = TerminalUi;

    edit_single_field(
        &mut identity,
        "email",
        Some("new@example.com".to_string()),
        &ui,
    )
    .unwrap();
    assert_eq!(identity.email.as_deref(), Some("new@example.com"));

    // An empty string clears the field.
    edit_single_field(&mut identity, "email", Some(String::new()), &ui).unwrap();
    assert!(identity.email.is_none());

    edit_single_field(
        &mut identity,
        "phone",
        Some("+49123456789".to_string()),
        &ui,
    )
    .unwrap();
    assert_eq!(identity.phone.as_deref(), Some("+49123456789"));
    edit_single_field(&mut identity, "phone", Some(String::new()), &ui).unwrap();
    assert!(identity.phone.is_none());

    edit_single_field(&mut identity, "description", Some("fresh".to_string()), &ui).unwrap();
    assert_eq!(identity.description, "fresh");

    edit_single_field(&mut identity, "type", Some("work".to_string()), &ui).unwrap();
    assert_eq!(identity.identity_type, "work");

    // Field matching is case-insensitive.
    edit_single_field(&mut identity, "DESCRIPTION", Some("upper".to_string()), &ui).unwrap();
    assert_eq!(identity.description, "upper");

    let err = edit_single_field(&mut identity, "bogus", Some("x".to_string()), &ui).unwrap_err();
    assert!(err.to_string().contains("Unknown field: bogus"));
}

#[test]
fn single_field_without_value_prompts_interactively() {
    let mut identity = sample_identity();

    // `type` without a value opens the selection menu.
    let ui = ScriptedUi::new().select(3); // → "gaming"
    edit_single_field(&mut identity, "type", None, &ui).unwrap();
    assert_eq!(identity.identity_type, "gaming");

    // `email`/`phone`/`description` without a value open a text prompt.
    let ui = ScriptedUi::new().input("");
    edit_single_field(&mut identity, "email", None, &ui).unwrap();
    assert!(identity.email.is_none());

    let ui = ScriptedUi::new().input("+49123456789");
    edit_single_field(&mut identity, "phone", None, &ui).unwrap();
    assert_eq!(identity.phone.as_deref(), Some("+49123456789"));

    let ui = ScriptedUi::new().input("brand new");
    edit_single_field(&mut identity, "description", None, &ui).unwrap();
    assert_eq!(identity.description, "brand new");
}

#[test]
fn edit_interactive_round_trip_with_scripted_answers() {
    let mut identity = sample_identity();

    // Outer menu: description → email → phone → tags → type →
    // custom attributes → done. Inside the attribute menu: add → edit →
    // remove → edit (empty early-return) → remove (empty early-return) →
    // done. Then the outer menu is closed with "Done".
    let ui = ScriptedUi::new()
        .select(1)
        .input("scripted description")
        .select(2)
        .input("") // clears the email
        .select(3)
        .input("+49123456789")
        .select(4)
        .input("a, b, c")
        .select(0)
        .select(1) // type menu → "work"
        .select(5)
        .select(0) // add attribute
        .input("role")
        .input("admin")
        .select(1) // edit existing attribute
        .select(0) // pick "role"
        .input("super-admin")
        .select(2) // remove attribute
        .multi_select(&[0])
        .select(1) // edit existing — list is empty again, early return
        .select(2) // remove attribute — list is empty again, early return
        .select(3) // done with attributes
        .select(6); // done with editor

    edit_interactive(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());

    assert_eq!(identity.description, "scripted description");
    assert!(identity.email.is_none());
    assert_eq!(identity.phone.as_deref(), Some("+49123456789"));
    assert_eq!(identity.tags, vec!["a", "b", "c"]);
    assert_eq!(identity.identity_type, "work");
    // The attribute was added, edited, then removed again.
    assert!(identity.attributes.is_empty());
}

#[test]
fn edit_from_args_applies_only_present_fields() {
    let mut identity = sample_identity();
    let args = EditArgs {
        name: identity.name.clone(),
        identity_type: Some("work".to_string()),
        description: Some("updated".to_string()),
        email: Some(String::new()),
        phone: Some("+491234567890".to_string()),
        interactive: false,
        field: None,
        value: None,
    };
    edit_from_args(&mut identity, &args).unwrap();
    assert_eq!(identity.identity_type, "work");
    assert_eq!(identity.description, "updated");
    assert!(identity.email.is_none());
    assert_eq!(identity.phone.as_deref(), Some("+491234567890"));

    // Non-empty email/phone keep their values (the Some(...) arm).
    let mut identity = sample_identity();
    identity.email = None;
    identity.phone = None;
    let args = EditArgs {
        name: identity.name.clone(),
        identity_type: None,
        description: None,
        email: Some("kept@example.com".to_string()),
        phone: Some("+49111222333".to_string()),
        interactive: false,
        field: None,
        value: None,
    };
    edit_from_args(&mut identity, &args).unwrap();
    assert_eq!(identity.email.as_deref(), Some("kept@example.com"));
    assert_eq!(identity.phone.as_deref(), Some("+49111222333"));
}

#[test]
fn edit_identity_type_falls_back_to_first_option_for_unknown_types() {
    let mut identity = sample_identity();
    identity.identity_type = "custom-thing".to_string();

    // The current type is not in the menu, so the pre-selection falls
    // back to index 0 ("personal"); picking index 2 selects "social".
    let ui = ScriptedUi::new().select(2);
    edit_identity_type(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());
    assert_eq!(identity.identity_type, "social");
}

#[test]
fn edit_from_args_empty_phone_clears_the_field() {
    let mut identity = sample_identity();
    identity.phone = Some("+49123456789".to_string());
    let args = EditArgs {
        name: identity.name.clone(),
        identity_type: None,
        description: None,
        email: None,
        phone: Some(String::new()),
        interactive: false,
        field: None,
        value: None,
    };
    edit_from_args(&mut identity, &args).unwrap();
    assert!(identity.phone.is_none());
}

#[tokio::test]
async fn edit_interactive_sets_and_clears_email_and_phone() {
    let mut identity = sample_identity();
    identity.email = None;
    identity.phone = None;

    // email → type a new address; phone → clear it (already empty).
    let ui = ScriptedUi::new()
        .select(2)
        .input("fresh@example.com")
        .select(3)
        .input("")
        .select(6); // done
    edit_interactive(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());
    assert_eq!(identity.email.as_deref(), Some("fresh@example.com"));
    assert!(identity.phone.is_none());
}
