use persona_core::auth::{MockRemoteAuthProvider, RemoteAuthProvider};

#[test]
fn mock_remote_auth_round_trip() {
    let provider = MockRemoteAuthProvider;
    let challenge = provider.begin("alice@example.com").expect("begin failed");
    let result = provider
        .finalize(&challenge, "client_proof")
        .expect("finalize failed");
    assert_eq!(result.user_id, challenge.user_id);
    assert_eq!(result.proof.client_proof, "client_proof");
    assert_eq!(result.proof.server_proof, "server_proof_placeholder");
    assert_eq!(result.session_key_fingerprint, "mock_session_fingerprint");
}
