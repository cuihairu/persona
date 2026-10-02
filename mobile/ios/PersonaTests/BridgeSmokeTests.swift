import XCTest
@testable import Persona

/// 桥冒烟：staticlib 在真机/模拟器链接成功后运行；CI 无 macOS runner，
/// 本套件留给 macOS 实机验收跑（xcodebuild test）。
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
        // 未初始化时锁定失败或成功（幂等）都属合法行为，断言不崩溃即可
    }
}
