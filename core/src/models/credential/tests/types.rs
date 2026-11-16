use super::*;

#[test]
fn credential_type_display_values() {
    assert_eq!(CredentialType::Password.to_string(), "Password");
    assert_eq!(CredentialType::CryptoWallet.to_string(), "CryptoWallet");
    assert_eq!(CredentialType::SshKey.to_string(), "SshKey");
    assert_eq!(CredentialType::TwoFactor.to_string(), "TwoFactor");
    assert_eq!(
        CredentialType::Custom("X".to_string()).to_string(),
        "X".to_string()
    );
}

#[test]
fn security_level_display_values() {
    assert_eq!(SecurityLevel::Critical.to_string(), "Critical");
    assert_eq!(SecurityLevel::High.to_string(), "High");
    assert_eq!(SecurityLevel::Medium.to_string(), "Medium");
    assert_eq!(SecurityLevel::Low.to_string(), "Low");
}

#[test]
fn credential_type_display_remaining_values() {
    assert_eq!(CredentialType::ApiKey.to_string(), "ApiKey");
    assert_eq!(CredentialType::BankCard.to_string(), "BankCard");
    assert_eq!(CredentialType::GameAccount.to_string(), "GameAccount");
    assert_eq!(CredentialType::ServerConfig.to_string(), "ServerConfig");
    assert_eq!(CredentialType::Certificate.to_string(), "Certificate");
    assert_eq!(CredentialType::SecureNote.to_string(), "SecureNote");
    assert_eq!(CredentialType::Identity.to_string(), "Identity");
    assert_eq!(
        CredentialType::SoftwareLicense.to_string(),
        "SoftwareLicense"
    );
}

#[test]
fn credential_type_from_str_roundtrips_all_known_variants() {
    for name in [
        "Password",
        "CryptoWallet",
        "SshKey",
        "ApiKey",
        "BankCard",
        "GameAccount",
        "ServerConfig",
        "Certificate",
        "TwoFactor",
        "SecureNote",
        "Identity",
        "SoftwareLicense",
    ] {
        let parsed: CredentialType = name.parse().unwrap();
        assert_eq!(parsed.to_string(), name, "roundtrip must hold for {name}");
    }

    // 未知串不报错，归入 Custom 并保留原文
    let custom: CredentialType = "LoyaltyCard".parse().unwrap();
    assert_eq!(custom, CredentialType::Custom("LoyaltyCard".to_string()));
    assert_eq!(custom.to_string(), "LoyaltyCard");
}

#[test]
fn security_level_from_str_rejects_unknown() {
    let low: SecurityLevel = "Low".parse().unwrap();
    assert_eq!(low, SecurityLevel::Low);
    assert_eq!(
        "Critical".parse::<SecurityLevel>().unwrap(),
        SecurityLevel::Critical
    );
    assert_eq!(
        "High".parse::<SecurityLevel>().unwrap(),
        SecurityLevel::High
    );
    assert_eq!(
        "Medium".parse::<SecurityLevel>().unwrap(),
        SecurityLevel::Medium
    );

    let err = "extreme".parse::<SecurityLevel>().unwrap_err();
    assert_eq!(err, "Unknown security level: extreme");
}

// serde 派生覆盖全部字段：is_active/is_favorite/metadata 也要在
// roundtrip 里断言（序列化/反序列化的字段赋值行才全部落地）。
