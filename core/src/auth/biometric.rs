use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{PersonaError, Result};

/// Supported biometric platforms (abstracted to keep the core crate cross-platform).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BiometricPlatform {
    TouchId,
    FaceId,
    WindowsHello,
    LinuxSecretService,
    Unknown,
}

/// Client-provided hint for biometric unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricPrompt {
    pub user_id: Uuid,
    pub reason: String,
    pub platform: Option<BiometricPlatform>,
}

/// Result of a biometric verification attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricAuthResult {
    pub user_id: Uuid,
    pub verified: bool,
    pub platform: BiometricPlatform,
}

/// Abstraction for platform-specific biometric unlock hooks.
pub trait BiometricProvider: Send + Sync {
    /// Whether biometric hardware/OS APIs are available.
    fn is_available(&self, hint: Option<BiometricPlatform>) -> bool;

    /// Perform a biometric authentication ceremony.
    fn authenticate(&self, prompt: &BiometricPrompt) -> Result<BiometricAuthResult>;
}

/// In-memory mock that simulates biometric success/failure.
#[derive(Debug, Clone)]
pub struct MockBiometricProvider {
    pub available: bool,
    pub force_fail: bool,
    pub platform: BiometricPlatform,
}

impl Default for MockBiometricProvider {
    fn default() -> Self {
        Self {
            available: true,
            force_fail: false,
            platform: BiometricPlatform::Unknown,
        }
    }
}

impl BiometricProvider for MockBiometricProvider {
    fn is_available(&self, hint: Option<BiometricPlatform>) -> bool {
        self.available
            && hint.map_or(true, |h| {
                h == self.platform || self.platform == BiometricPlatform::Unknown
            })
    }

    fn authenticate(&self, prompt: &BiometricPrompt) -> Result<BiometricAuthResult> {
        if !self.is_available(prompt.platform) {
            return Err(
                PersonaError::AuthenticationFailed("Biometric unavailable".to_string()).into(),
            );
        }

        if self.force_fail {
            return Err(PersonaError::AuthenticationFailed(
                "Biometric verification failed".to_string(),
            )
            .into());
        }

        Ok(BiometricAuthResult {
            user_id: prompt.user_id,
            verified: true,
            platform: prompt.platform.unwrap_or(self.platform),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_success() {
        let provider = MockBiometricProvider::default();
        let prompt = BiometricPrompt {
            user_id: Uuid::new_v4(),
            reason: "unlock".to_string(),
            platform: Some(BiometricPlatform::TouchId),
        };
        let result = provider.authenticate(&prompt).unwrap();
        assert!(result.verified);
        assert_eq!(result.user_id, prompt.user_id);
    }

    #[test]
    fn mock_failure_when_unavailable() {
        let provider = MockBiometricProvider {
            available: false,
            ..Default::default()
        };
        let prompt = BiometricPrompt {
            user_id: Uuid::new_v4(),
            reason: "unlock".to_string(),
            platform: None,
        };
        let err = provider.authenticate(&prompt).unwrap_err();
        assert!(err.to_string().contains("Biometric unavailable"));
    }

    #[test]
    fn mock_failure_on_force_fail() {
        let provider = MockBiometricProvider {
            force_fail: true,
            ..Default::default()
        };
        let prompt = BiometricPrompt {
            user_id: Uuid::new_v4(),
            reason: "unlock".to_string(),
            platform: None,
        };
        let err = provider.authenticate(&prompt).unwrap_err();
        assert!(err.to_string().contains("Biometric verification failed"));
    }
}
