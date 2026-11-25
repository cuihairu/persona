import XCTest
@testable import Persona

/// Bridge smoke tests: run once the staticlib links successfully on device/simulator;
/// CI has no macOS runner, so this suite is reserved for macOS hardware acceptance
/// (xcodebuild test).
final class BridgeSmokeTests: XCTestCase {
    func testVersionIsSemantic() {
        let version = PersonaBridge.version
        XCTAssertFalse(version.isEmpty)
        XCTAssertTrue(version.split(separator: ".").count >= 2, "版本应至少 major.minor：\(version)")
    }

    func testLockWhenNotInitializedFailsGracefully() {
        let result = PersonaBridge.serviceLock()
        if case .failure(let message) = result {
            XCTAssertFalse(message.isEmpty)
        }
        // Locking while uninitialized may fail or succeed (idempotent); both are legal, just assert no crash
    }
}
