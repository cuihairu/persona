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

    // ---- Business envelope parsing (PERSONA-MOBILE-002 remote FFI out-shape).
    // Pure Swift: no bridge calls, runs anywhere the test bundle compiles. ----

    func testParseBusinessReadsSuccessEnvelope() {
        let envelope = PersonaBridge.parseBusiness(#"{"ok":true,"data":{"token":"t1","expires_in_secs":900}}"#)
        XCTAssertTrue(envelope.ok)
        XCTAssertNil(envelope.error)
        XCTAssertEqual(envelope.data?["token"] as? String, "t1")
        XCTAssertEqual(envelope.data?["expires_in_secs"] as? Int, 900)
    }

    func testParseBusinessReadsErrorEnvelope() {
        let envelope = PersonaBridge.parseBusiness(#"{"ok":false,"error":"login failed"}"#)
        XCTAssertFalse(envelope.ok)
        XCTAssertEqual(envelope.error, "login failed")
        XCTAssertNil(envelope.data)
    }

    func testParseBusinessNullLandsInFailureArm() {
        let envelope = PersonaBridge.parseBusiness(nil)
        XCTAssertFalse(envelope.ok)
        XCTAssertNotNil(envelope.error)
    }

    func testParseBusinessNonJsonLandsInFailureArm() {
        let envelope = PersonaBridge.parseBusiness("not json at all")
        XCTAssertFalse(envelope.ok)
    }
}
