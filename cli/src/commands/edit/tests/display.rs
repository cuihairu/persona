use super::*;

#[test]
fn show_current_values_prints_every_optional_section() {
    let mut identity = sample_identity();
    identity.phone = Some("+49123456789".to_string());
    identity
        .attributes
        .insert("role".to_string(), Value::String("admin".to_string()));

    // Rendering every optional section must not panic.
    show_current_values(&identity).unwrap();
}
