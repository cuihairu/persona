use persona_core::auth::{
    BiometricPlatform, BiometricPrompt, BiometricProvider, MockBiometricProvider,
};
use uuid::Uuid;

#[test]
fn biometric_success() {
    let provider = MockBiometricProvider::default();
    let prompt = BiometricPrompt {
        user_id: Uuid::new_v4(),
        reason: "unlock vault".to_string(),
        platform: Some(BiometricPlatform::TouchId),
    };
    assert!(provider.is_available(prompt.platform));
    let result = provider.authenticate(&prompt).unwrap();
    assert!(result.verified);
}

#[test]
fn biometric_unavailable_errors() {
    let provider = MockBiometricProvider {
        available: false,
        ..Default::default()
    };
    let prompt = BiometricPrompt {
        user_id: Uuid::new_v4(),
        reason: "unlock".to_string(),
        platform: None,
    };
    assert!(!provider.is_available(None));
    assert!(provider.authenticate(&prompt).is_err());
}
