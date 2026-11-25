import Foundation
import PersonaFFI

/// Swift wrapper over the persona-mobile staticlib: C ABI -> Swift-friendly types.
/// Out parameters are uniformly Result<Void, String>; PersonaResult.error_message
/// is returned via persona_free_result immediately after being consumed, to avoid leaks.
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

    /// Convert the C struct result into a Swift Result and return ownership of error_message
    private static func settle(_ r: PersonaResult) -> Result<Void, String> {
        if r.success { return .success(()) }
        let message = r.error_message.map { String(cString: $0) } ?? "Unknown error"
        persona_free_result(r)
        return .failure(message)
    }
}
