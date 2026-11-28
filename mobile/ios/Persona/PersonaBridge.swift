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

    // ---- Remote auth FFI (business envelope) — the mobile side of the
    // server's login-awareness surface. These calls block on the native
    // tokio runtime: callers must keep them off the main thread. ----

    /** Bootstrap SRP registration; the password chosen here is the login password */
    static func remoteRegisterDevice(baseUrl: String, bearer: String, deviceName: String,
                                     password: String) -> String? {
        baseUrl.withCString { base in
            bearer.withCString { bea in
                deviceName.withCString { dev in
                    password.withCString { pw in
                        ownedString(persona_remote_register_device(base, bea, dev, pw))
                    }
                }
            }
        }
    }

    /** SRP login: reports this device's fingerprint to the server ledger and
     * returns the short-lived Bearer token inside data */
    static func remoteLogin(baseUrl: String, deviceName: String,
                            password: String) -> String? {
        baseUrl.withCString { base in
            deviceName.withCString { dev in
                password.withCString { pw in
                    ownedString(persona_remote_login(base, dev, pw))
                }
            }
        }
    }

    /** Login-awareness device registry (server JSON passed through in data) */
    static func remoteDevices(baseUrl: String, token: String) -> String? {
        baseUrl.withCString { base in
            token.withCString { tok in
                ownedString(persona_remote_devices(base, tok))
            }
        }
    }

    /// Lightweight unwrap of the business envelope: null / non-JSON always
    /// land in the failure arm, no exception thrown.
    static func parseBusiness(_ json: String?) -> BusinessEnvelope {
        guard let json = json, let raw = json.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any]
        else {
            return BusinessEnvelope(ok: false, error: "Unexpected native response", data: nil)
        }
        let error = (obj["error"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return BusinessEnvelope(ok: obj["ok"] as? Bool ?? false,
                                error: error,
                                data: obj["data"] as? [String: Any])
    }

    /// Take ownership of a heap C string returned by the FFI (may be NULL).
    /// The FFI returns `const char *` (UnsafePointer) while persona_free_string
    /// takes `char *` (UnsafeMutablePointer) — convert via the mutating init,
    /// same pattern as persona_version above.
    private static func ownedString(_ p: UnsafePointer<CChar>?) -> String? {
        guard let p = p else { return nil }
        defer { persona_free_string(UnsafeMutablePointer(mutating: p)) }
        return String(cString: p)
    }

    /// Convert the C struct result into a Swift Result and return ownership of error_message
    private static func settle(_ r: PersonaResult) -> Result<Void, String> {
        if r.success { return .success(()) }
        let message = r.error_message.map { String(cString: $0) } ?? "Unknown error"
        persona_free_result(r)
        return .failure(message)
    }
}

/// Parsed business envelope: ok flag, error message and the data payload.
/// data is the payload object itself (callers read keys directly from it).
struct BusinessEnvelope {
    let ok: Bool
    let error: String?
    let data: [String: Any]?
}
