use super::*;

#[test]
fn parse_use_case_labels_cover_all_aliases() {
    assert!(matches!(
        parse_use_case_label("personal").unwrap(),
        AutoLockUseCase::PersonalDevice
    ));
    assert!(matches!(
        parse_use_case_label("corporate_desktop").unwrap(),
        AutoLockUseCase::CorporateDesktop
    ));
    assert!(matches!(
        parse_use_case_label("kiosk").unwrap(),
        AutoLockUseCase::PublicKiosk
    ));
    assert!(matches!(
        parse_use_case_label("dev").unwrap(),
        AutoLockUseCase::DeveloperEnvironment
    ));
    assert!(matches!(
        parse_use_case_label("High-Security").unwrap(),
        AutoLockUseCase::HighSecurityFacility
    ));
    let err = parse_use_case_label("bogus").unwrap_err();
    assert!(err.to_string().contains("Unsupported use case 'bogus'"));
}
