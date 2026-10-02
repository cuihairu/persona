import Foundation
import PersonaFFI

/// persona-mobile staticlib 的 Swift 封装：C ABI → Swift 友好类型。
/// 出参统一 Result<Void, String>；PersonaResult.error_message 消费后
/// 立即经 persona_free_result 归还，避免泄漏。
enum PersonaBridge {

    static var version: String {
        let c = persona_version()!
        defer { persona_free_string(UnsafeMutablePointer(mutating: c)) }
        return String(cString: c)
    }

    static func serviceInit(dbPath: String, masterPassword: String) -> Result<Void, String> {
        dbPath.withCString { db in
            masterPassword.withCString { pw in
                let r = persona_service_init(db, pw)
                return settle(r)
            }
        }
    }

    static func serviceUnlock(masterPassword: String) -> Result<Void, String> {
        masterPassword.withCString { pw in
            settle(persona_service_unlock(pw))
        }
    }

    static func serviceLock() -> Result<Void, String> {
        settle(persona_service_lock())
    }

    static var isUnlocked: Bool {
        persona_service_is_unlocked()
    }

    static func shutdown() -> Result<Void, String> {
        settle(persona_shutdown())
    }

    /// 把 C 结构结果转成 Swift Result 并归还 error_message 所有权
    private static func settle(_ r: PersonaResult) -> Result<Void, String> {
        if r.success { return .success(()) }
        let message = r.error_message.map { String(cString: $0) } ?? "Unknown error"
        persona_free_result(r)
        return .failure(message)
    }
}
