use super::*;

/// Bytes that historically break JSON/base64/UTF-8 parsers.
const HOSTILE_BYTES: [u8; 5] = [0xFF, 0x00, b'\n', b'"', 0x80];

// ============ §12 fuzz list: deterministic malformed-input harness ============
//
// docs/PASSKEYS_DESIGN.md §12 puts `clientDataJSON` and creation-options JSON
// parsing on the fuzz list. This repo has no cargo-fuzz/libFuzzer scaffolding
// (no fuzz/ dir, no nightly toolchain), so instead of a nightly-only harness
// these tests drive the three parsing entry points with a hand-written,
// deterministic PRNG over mutation strategies drawn from real-world parser
// breakage: bit flips, truncation, span deletion, hostile-byte injection,
// JSON fragment splicing and wholesale random bytes. The property is always
// "malformed input yields Err (or a self-consistent Ok), never a panic".
// When a real fuzz target lands, hook these same entry points and properties.

/// xorshift64* — hand-rolled so the suite does not depend on any particular
/// `rand` API; same seed ⇒ same sequence, so failures are reproducible.
struct DetRng(u64);

impl DetRng {
    fn new(seed: u64) -> Self {
        // xorshift's only fixed point is 0 — keep the state off it.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform enough in `[0, n)`; callers guarantee `n > 0`.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// One deterministic mutation of `seed`.
fn mutate_bytes(rng: &mut DetRng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        out.push(HOSTILE_BYTES[rng.below(HOSTILE_BYTES.len())]);
        return out;
    }
    match rng.below(6) {
        0 => {
            // Single bit flip.
            let i = rng.below(out.len());
            out[i] ^= 1u8 << rng.below(8);
        }
        1 => {
            // Truncation — mid-JSON cuts.
            out.truncate(rng.below(out.len() + 1));
        }
        2 => {
            // Delete a run.
            let start = rng.below(out.len());
            let end = (start + 1 + rng.below(out.len() - start)).min(out.len());
            out.drain(start..end);
        }
        3 => {
            // Inject hostile bytes.
            let at = rng.below(out.len() + 1);
            let inj: Vec<u8> = (0..1 + rng.below(3))
                .map(|_| HOSTILE_BYTES[rng.below(HOSTILE_BYTES.len())])
                .collect();
            out.splice(at..at, inj);
        }
        4 => {
            // Splice in a JSON fragment.
            const FRAGMENTS: [&[u8]; 6] = [
                br#"{"type":"#,
                br#""challenge":""#,
                b"null",
                b"[",
                br#""origin":"evil.example""#,
                b"\"",
            ];
            let frag = FRAGMENTS[rng.below(FRAGMENTS.len())];
            let start = rng.below(out.len());
            let end = (start + rng.below(out.len() - start + 1)).min(out.len());
            out.splice(start..end, frag.iter().copied());
        }
        _ => {
            // Wholesale replacement with random bytes.
            out = (0..1 + rng.below(96))
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect();
        }
    }
    out
}

/// Mangle the field at `path` (dot-separated, e.g. `"user.id"`) inside
/// `value`: delete it, or replace it with a hostile-typed value. Returns
/// `false` (value untouched) if any hop along the path is missing.
fn mangle_field(rng: &mut DetRng, value: &mut serde_json::Value, path: &str) -> bool {
    const REPLACEMENTS: usize = 4;
    let mut segs: Vec<&str> = path.split('.').collect();
    let Some(leaf) = segs.pop() else {
        return false;
    };
    let mut cur = value;
    for seg in segs {
        match cur.get_mut(seg) {
            Some(next) => cur = next,
            None => return false,
        }
    }
    if cur.get(leaf).is_none() {
        return false;
    }
    match rng.below(5) {
        0 => {
            // Field deletion.
            if let Some(obj) = cur.as_object_mut() {
                obj.remove(leaf);
            }
        }
        _ => {
            // Wrong-typed replacement.
            let replacement = match rng.below(REPLACEMENTS) {
                0 => serde_json::Value::Null,
                1 => serde_json::json!(rng.next_u64() as i64),
                2 => serde_json::json!("\u{10FFFF}"),
                _ => serde_json::json!([null, "Y2hhbGxlbmdl", 42]),
            };
            if let Some(slot) = cur.get_mut(leaf) {
                *slot = replacement;
            }
        }
    }
    true
}

/// One deterministic structural mutation of a creation-options Value.
fn mutate_value(rng: &mut DetRng, base: &serde_json::Value) -> serde_json::Value {
    const PATHS: [&str; 8] = [
        "user",
        "user.id",
        "user.name",
        "user.displayName",
        "rp",
        "rp.id",
        "pubKeyCredParams",
        "pubKeyCredParams.0.alg",
    ];
    let mut out = base.clone();
    let path = PATHS[rng.below(PATHS.len())];
    let _ = mangle_field(rng, &mut out, path);
    out
}

/// A deterministic hostile string: scheme/port punctuation plus bytes that
/// are not valid UTF-8 (lossily converted — the parsers see what a browser
/// wire would give them).
fn random_hostile_string(rng: &mut DetRng) -> String {
    const ALPHA: &[u8] = b"abc.-_:/\x80\xFF%?&=";
    let bytes: Vec<u8> = (0..rng.below(40))
        .map(|_| ALPHA[rng.below(ALPHA.len())])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Self-consistency of a successful `parse_creation_options` result against
/// the very options value it accepted.
fn assert_options_ok_invariants(
    iter: usize,
    parsed: &ParsedCreationOptions,
    options: &serde_json::Value,
    origin: &str,
) {
    assert!(
        !parsed.user_handle.is_empty() && parsed.user_handle.len() <= 64,
        "iteration {iter}: user_handle must stay within WebAuthn §5.4.2 bounds, got {} bytes",
        parsed.user_handle.len()
    );
    let claimed_rp = options
        .get("rp")
        .and_then(|rp| rp.get("id"))
        .and_then(|v| v.as_str());
    match claimed_rp {
        Some(id) => assert_eq!(
            parsed.rp_id, id,
            "iteration {iter}: rp_id must echo rp.id when present"
        ),
        None => assert_eq!(
            parsed.rp_id,
            origin_host(origin).expect("Ok parse implies origin_host(origin) succeeds"),
            "iteration {iter}: rp_id must default to the origin host when rp.id is absent"
        ),
    }
}

#[test]
fn fuzz_parse_client_data_never_panics_on_malformed_input() {
    const ORIGIN: &str = "https://example.com";
    let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0001);

    // The clean seeds must parse — otherwise the loop below could be vacuous.
    for (create, expected_type) in [
        (true, CLIENT_DATA_TYPE_CREATE),
        (false, CLIENT_DATA_TYPE_GET),
    ] {
        let seed = client_data(create, "Y2hhbGxlbmdl", ORIGIN);
        let parsed = parse_client_data(&seed, expected_type, ORIGIN)
            .expect("clean clientDataJSON must parse");
        assert!(parsed.origin.eq_ignore_ascii_case(ORIGIN));
    }

    let mut accepted = 0usize;
    for i in 0..2_000 {
        let (create, expected_type) = if i % 2 == 0 {
            (true, CLIENT_DATA_TYPE_CREATE)
        } else {
            (false, CLIENT_DATA_TYPE_GET)
        };
        let seed = client_data(create, "Y2hhbGxlbmdl", ORIGIN);
        let input = mutate_bytes(&mut rng, &seed);
        if let Ok(parsed) = parse_client_data(&input, expected_type, ORIGIN) {
            // Accepting a mutated blob is only sound if the acceptance
            // contract still holds: the transport-verified origin matched
            // (case-insensitively, per impl) and the challenge is decodable.
            assert!(
                parsed.origin.eq_ignore_ascii_case(ORIGIN),
                "iteration {i}: accepted origin {:?} must equal {ORIGIN}",
                parsed.origin
            );
            assert!(
                decode_b64url(&parsed.challenge).is_ok(),
                "iteration {i}: accepted challenge {:?} must be base64url",
                parsed.challenge
            );
            accepted += 1;
        }
    }
    // Deterministic seed ⇒ fixed sequence: if this ever drops to zero the
    // mutation mix stopped reaching the acceptance path and the property
    // above has become vacuous.
    assert!(
        accepted > 0,
        "no mutated input was ever accepted — the Ok-path property above is vacuous"
    );

    // Fail-closed anchors: a deterministic checklist from §12's malformed
    // input list — each must produce Err, not a panic and not a pass.
    let anchors: [&[u8]; 7] = [
        b"",
        b"\xFF\xFE\xFD",                                   // invalid UTF-8
        br#"{"type":"webauthn.create","challenge":"Y2hh"#, // truncated JSON
        br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#, // wrong ceremony
        br#"{"type":"webauthn.create","challenge":"!!not-b64!!","origin":"https://example.com"}"#, // bad base64url
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://evil.example"}"#, // origin mismatch
        br#"{"type":"webauthn.create"}"#, // missing fields
    ];
    for (i, anchor) in anchors.iter().enumerate() {
        assert!(
            parse_client_data(anchor, CLIENT_DATA_TYPE_CREATE, ORIGIN).is_err(),
            "anchor {i} {:?} must be rejected",
            String::from_utf8_lossy(anchor)
        );
    }
}

#[test]
fn fuzz_parse_creation_options_never_panics_on_malformed_input() {
    const ORIGIN: &str = "https://example.com";
    let base = es256_options(Some("example.com"), Some("dXNlcg"));
    let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0002);

    // The clean fixture must parse — otherwise both loops could be vacuous.
    parse_creation_options(&base, ORIGIN).expect("clean options must parse");

    // Layer 1: hostile JSON *text*. Most mutations stop at the serde gate;
    // whenever the text still deserializes, the semantic parser must take
    // the same no-panic guarantee.
    let base_text = serde_json::to_string(&base).expect("fixture serializes");
    let mut text_ok = 0usize;
    for i in 0..1_000 {
        let text = mutate_bytes(&mut rng, base_text.as_bytes());
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&text) {
            if let Ok(parsed) = parse_creation_options(&value, ORIGIN) {
                assert_options_ok_invariants(i, &parsed, &value, ORIGIN);
                text_ok += 1;
            }
        }
    }
    // Deterministic seed ⇒ fixed sequence: both counters are vacuity guards
    // for the property above, same rationale as the client-data loop.
    assert!(
        text_ok > 0,
        "no mutated JSON text was ever accepted — layer 1 is vacuous"
    );

    // Layer 2: structurally valid JSON whose fields are hostile — reaches
    // the semantic arms the serde layer cannot filter out.
    let mut struct_ok = 0usize;
    for i in 0..1_000 {
        let value = mutate_value(&mut rng, &base);
        if let Ok(parsed) = parse_creation_options(&value, ORIGIN) {
            assert_options_ok_invariants(i, &parsed, &value, ORIGIN);
            struct_ok += 1;
        }
    }
    assert!(
        struct_ok > 0,
        "no structurally mutated options were ever accepted — layer 2 is vacuous"
    );

    // Fail-closed anchors: semantic rejections the random layers may miss.
    let mut no_es256 = es256_options(Some("example.com"), Some("dXNlcg"));
    no_es256["pubKeyCredParams"] = serde_json::json!([{"type": "public-key", "alg": -257}]);

    let mut empty_id = es256_options(Some("example.com"), Some("dXNlcg"));
    empty_id["user"]["id"] = serde_json::json!("");

    let mut long_id = es256_options(Some("example.com"), Some("dXNlcg"));
    // 87 unpadded b64url chars decode to exactly 65 bytes (§5.4.2 max is 64).
    long_id["user"]["id"] = serde_json::json!("A".repeat(87));

    let mut nonstr_id = es256_options(Some("example.com"), Some("dXNlcg"));
    nonstr_id["user"]["id"] = serde_json::json!(42);

    let mut bad_b64_id = es256_options(Some("example.com"), Some("dXNlcg"));
    bad_b64_id["user"]["id"] = serde_json::json!("!!not-b64!!");

    for (anchor, why) in [
        (serde_json::json!({}), "empty options object"),
        (no_es256, "pubKeyCredParams without ES256 (alg -7)"),
        (empty_id, "user.id empty"),
        (long_id, "user.id decoding to 65 bytes"),
        (nonstr_id, "user.id not a string"),
        (bad_b64_id, "user.id not base64url"),
    ] {
        assert!(
            parse_creation_options(&anchor, ORIGIN).is_err(),
            "anchor [{why}] must be rejected"
        );
    }
}

#[test]
fn fuzz_validate_origin_matches_rp_id_never_panics() {
    let mut rng = DetRng::new(0x0FA1_1CE5_EED0_0003);

    // Anchors around the registrable-domain approximation. The suffix- and
    // prefix-confusion cases are the security-critical ones: an attacker
    // domain must never be accepted for a victim rp_id.
    for (origin, rp, must_pass, why) in [
        ("https://example.com", "example.com", true, "exact match"),
        ("https://sub.example.com", "example.com", true, "subdomain"),
        (
            "http://localhost:8080",
            "localhost",
            true,
            "localhost with port",
        ),
        (
            "https://EXAMPLE.com",
            "example.COM",
            true,
            "case-insensitive match",
        ),
        (
            "https://evil-github.com",
            "github.com",
            false,
            "suffix confusion",
        ),
        (
            "https://github.com.evil.example",
            "github.com",
            false,
            "prefix confusion",
        ),
        (
            "https://github.com",
            "com",
            false,
            "public-suffix-only rp_id",
        ),
        (
            "https://github.com",
            "github.com.",
            false,
            "trailing-dot rp_id",
        ),
        (
            "https://github.com",
            "https://github.com",
            false,
            "rp_id is a URL",
        ),
        ("github.com", "github.com", false, "scheme-less origin"),
        ("https://", "github.com", false, "origin without host"),
        ("", "", false, "empty inputs"),
    ] {
        let result = validate_origin_matches_rp_id(origin, rp);
        assert_eq!(
            result.is_ok(),
            must_pass,
            "origin={origin:?} rp_id={rp:?} ({why}) -> {:?}",
            result.err().map(|e| e.to_string())
        );
    }

    // Random hostile pairs: never panic; acceptance must always satisfy the
    // "host == rp_id or host is a subdomain of rp_id" contract.
    let base_origin = "https://example.com";
    let base_rp = "example.com";
    for i in 0..600 {
        let origin = if i % 3 == 0 {
            String::from_utf8_lossy(&mutate_bytes(&mut rng, base_origin.as_bytes())).into_owned()
        } else {
            random_hostile_string(&mut rng)
        };
        let rp = if i % 3 == 0 {
            String::from_utf8_lossy(&mutate_bytes(&mut rng, base_rp.as_bytes())).into_owned()
        } else {
            random_hostile_string(&mut rng)
        };
        if validate_origin_matches_rp_id(&origin, &rp).is_ok() {
            let host = origin_host(&origin).expect("Ok verdict implies origin_host(origin) works");
            let rp_checked =
                validate_rp_id(&rp).expect("Ok verdict implies validate_rp_id(rp) works");
            assert!(
                host == rp_checked || host.ends_with(&format!(".{rp_checked}")),
                "iteration {i}: accepted origin={origin:?} rp_id={rp:?} but host={host:?} \
                     is neither equal to nor a subdomain of {rp_checked:?}"
            );
        }
    }
}
