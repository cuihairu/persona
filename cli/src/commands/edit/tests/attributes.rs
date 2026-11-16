use super::*;

#[test]
fn edit_and_remove_existing_attributes_directly() {
    let mut identity = sample_identity();
    identity
        .attributes
        .insert("role".to_string(), Value::String("admin".to_string()));
    identity
        .attributes
        .insert("team".to_string(), Value::String("core".to_string()));

    // Edit the second key in insertion order and retype its value.
    let keys: Vec<String> = identity.attributes.keys().cloned().collect();
    let target = keys.iter().position(|k| k == "team").unwrap();
    let ui = ScriptedUi::new().select(target).input("platform");
    edit_existing_attribute(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());
    assert_eq!(
        identity.attributes.get("team").and_then(|v| v.as_str()),
        Some("platform")
    );

    // Remove both attributes through the multi-select.
    let ui = ScriptedUi::new().multi_select(&[0, 1]);
    remove_custom_attribute(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());
    assert!(identity.attributes.is_empty());
}

/// The interactive main menu reaches the custom-attributes submenu,
/// edits one attribute there, and exits cleanly.
#[test]
fn edit_interactive_attributes_submenu_edits_and_exits() {
    let mut identity = sample_identity();
    identity
        .attributes
        .insert("role".to_string(), Value::String("admin".to_string()));

    // main: custom attributes → edit "role" → submenu done → main done.
    let ui = ScriptedUi::new()
        .select(5) // main menu: custom attributes
        .select(1) // submenu: edit existing attribute
        .select(0) // pick "role"
        .input("root")
        .select(3) // submenu: done
        .select(6); // main menu: done
    edit_interactive(&mut identity, &ui).unwrap();
    assert!(ui.exhausted());
    assert_eq!(
        identity.attributes.get("role").and_then(|v| v.as_str()),
        Some("root")
    );
}

/// Prompt failures inside the attribute helpers propagate (the `?` on
/// each scripted prompt) without mutating the identity.
#[test]
fn attribute_edit_and_remove_propagate_prompt_errors() {
    let mut identity = sample_identity();
    identity
        .attributes
        .insert("role".to_string(), Value::String("admin".to_string()));

    let inner = ScriptedUi::new();
    let ui = FailOn::new(&inner, PromptKind::Select);
    let err = edit_existing_attribute(&mut identity, &ui).unwrap_err();
    assert!(err.to_string().contains("failing ui: select prompt"));

    let inner = ScriptedUi::new().select(0);
    let ui = FailOn::new(&inner, PromptKind::Input);
    let err = edit_existing_attribute(&mut identity, &ui).unwrap_err();
    assert!(err.to_string().contains("failing ui: input prompt"));

    let inner = ScriptedUi::new();
    let ui = FailOn::new(&inner, PromptKind::MultiSelect);
    let err = remove_custom_attribute(&mut identity, &ui).unwrap_err();
    assert!(err.to_string().contains("failing ui: multi-select prompt"));
    assert_eq!(
        identity.attributes.get("role").and_then(|v| v.as_str()),
        Some("admin")
    );
}
