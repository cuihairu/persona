use super::*;

#[test]
fn validate_rp_id_shape_rules() {
    // dotted-only and scheme-carrying rp_ids are not hostnames
    let err = validate_rp_id(".").expect_err("dotted rp_id must be rejected");
    assert!(err.to_string().contains("Invalid rp_id"));
    let err =
        validate_rp_id("https://example.com").expect_err("rp_id with a scheme must be rejected");
    assert!(err.to_string().contains("rp_id must be a bare hostname"));
}

#[test]
fn origin_host_extraction_rules() {
    // Host is lower-cased; port, path, query and fragment are stripped.
    let parsed = parse_creation_options(
        &es256_options(None, Some("dQ")),
        "https://EXAMPLE.COM:8443/path?q=1#frag",
    )
    .unwrap();
    assert_eq!(parsed.rp_id, "example.com");

    // A scheme-less origin is rejected.
    let err = parse_creation_options(&es256_options(None, Some("dQ")), "example.com")
        .expect_err("scheme-less origin must be rejected");
    assert!(err.to_string().contains("Invalid origin"));
}

#[test]
fn validate_origin_matches_rp_id_rules() {
    // Exact match and subdomain match are fine.
    assert!(validate_origin_matches_rp_id("https://example.com", "example.com").is_ok());
    assert!(validate_origin_matches_rp_id("https://a.b.example.com", "example.com").is_ok());

    // A sibling domain is not a subdomain.
    let err = validate_origin_matches_rp_id("https://example.org", "example.com")
        .expect_err("different domain must be rejected");
    assert!(err.to_string().contains("does not match rp_id"));

    // rp_id shape rules apply to the direct call too.
    assert!(validate_origin_matches_rp_id("https://example.com", "https://example.com").is_err());
    assert!(validate_origin_matches_rp_id("https://example.com", "").is_err());
    assert!(validate_origin_matches_rp_id("https://example.com", ".").is_err());
}
