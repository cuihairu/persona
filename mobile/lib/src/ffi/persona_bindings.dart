// Generated Dart FFI bindings for persona-mobile Rust library.
// Mirrors the extern "C" functions in mobile/rust/src/lib.rs and business.rs.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:path_provider/path_provider.dart';

/// Opaque result struct returned by lifecycle FFI calls.
/// Mirrors `PersonaResult { bool success; char* error_message; }`
final class PersonaResult extends Struct {
  @Int32()
  external int success; // 0/1 as bool

  external Pointer<Utf8> errorMessage;
}

/// Loads the native library (libpersona_mobile.so) from the app's jniLibs.
DynamicLibrary _loadPersonaLib() {
  // On Android, the .so is bundled in jniLibs/arm64-v8a/ and loaded via System.loadLibrary.
  // The JNI_OnLoad path makes symbols available to dart:ffi via DynamicLibrary.process().
  // We also try explicit load as fallback.
  try {
    return DynamicLibrary.process(); // symbols from JNI_OnLoad
  } catch (_) {
    // Fallback: explicit path (works in debug when lib is extracted)
    final dir = Directory.systemTemp;
    final libPath = '${dir.path}/libpersona_mobile.so';
    if (File(libPath).existsSync()) {
      return DynamicLibrary.open(libPath);
    }
    // Last resort: process (may already be loaded by Flutter engine)
    return DynamicLibrary.process();
  }
}

DynamicLibrary? _lib;

/// Lazy accessor: loads the native library on first FFI call.
/// In tests (no native lib), this throws only when a function is actually invoked.
DynamicLibrary get _personaLib => _lib ??= _loadPersonaLib();

// -----------------------------------------------------------------------------
// Lifecycle FFI (lib.rs)
// -----------------------------------------------------------------------------

/// Initialize the mobile library. Returns 0 on success.
late final _personaInit = _personaLib
    .lookup<NativeFunction<Int32 Function()>>('persona_init')
    .asFunction<int Function()>();

/// Get version string. Caller must free with [personaFreeString].
late final _personaVersion = _personaLib
    .lookup<NativeFunction<Pointer<Utf8> Function()>>('persona_version')
    .asFunction<Pointer<Utf8> Function()>();

/// Free a string allocated by the library.
late final _personaFreeString = _personaLib
    .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('persona_free_string')
    .asFunction<void Function(Pointer<Utf8>)>();

/// Free a PersonaResult (frees error_message if non-null).
late final _personaFreeResult = _personaLib
    .lookup<NativeFunction<Void Function(PersonaResult)>>('persona_free_result')
    .asFunction<void Function(PersonaResult)>();

/// Initialize or re-initialize the Persona service (create user or authenticate).
/// db_path and master_password must be valid UTF-8 strings.
/// Returns PersonaResult (success=true on success, error_message on failure).
late final _personaServiceInit = _personaLib
    .lookup<
        NativeFunction<
            PersonaResult Function(
              Pointer<Utf8> dbPath,
              Pointer<Utf8> masterPassword,
            )>>('persona_service_init')
    .asFunction<PersonaResult Function(Pointer<Utf8>, Pointer<Utf8>)>();

/// Unlock existing session with master password.
late final _personaServiceUnlock = _personaLib
    .lookup<
        NativeFunction<
            PersonaResult Function(Pointer<Utf8> masterPassword)>>(
        'persona_service_unlock')
    .asFunction<PersonaResult Function(Pointer<Utf8>)>();

/// Lock immediately (clear in-memory keys).
late final _personaServiceLock = _personaLib
    .lookup<NativeFunction<PersonaResult Function()>>('persona_service_lock')
    .asFunction<PersonaResult Function()>();

/// Check if current session is unlocked.
late final _personaServiceIsUnlocked = _personaLib
    .lookup<NativeFunction<Int32 Function()>>('persona_service_is_unlocked')
    .asFunction<int Function()>();

/// Configure sync (audit event emitter). url and token both non-empty to enable;
/// either blank to disable (fail-closed).
late final _personaConfigureSync = _personaLib
    .lookup<
        NativeFunction<
            PersonaResult Function(
              Pointer<Utf8> serverUrl,
              Pointer<Utf8> token,
            )>>('persona_configure_sync')
    .asFunction<PersonaResult Function(Pointer<Utf8>, Pointer<Utf8>)>();

/// Shutdown: lock service, flush emitter, clear slots.
late final _personaShutdown = _personaLib
    .lookup<NativeFunction<PersonaResult Function()>>('persona_shutdown')
    .asFunction<PersonaResult Function()>();

// -----------------------------------------------------------------------------
// Business FFI (business.rs) — all return JSON string (caller frees with personaFreeString)
// -----------------------------------------------------------------------------

/// Create identity. Payload: JSON { name, identity_type, description?, email?, phone? }
late final _personaIdentityCreate = _personaLib
    .lookup<
        NativeFunction<
            Pointer<Utf8> Function(Pointer<Utf8> payload)>>(
        'persona_identity_create')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// List all identities. Returns JSON { ok: true, data: Identity[] } or { ok: false, error }.
late final _personaIdentityList = _personaLib
    .lookup<NativeFunction<Pointer<Utf8> Function()>>('persona_identity_list')
    .asFunction<Pointer<Utf8> Function()>();

/// Get single identity by UUID. Returns JSON envelope.
late final _personaIdentityGet = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> id)>>(
        'persona_identity_get')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Update identity. Payload: full Identity JSON (with id).
late final _personaIdentityUpdate = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> payload)>>(
        'persona_identity_update')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Delete identity by UUID. Returns JSON { ok: true, data: bool }.
late final _personaIdentityDelete = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> id)>>(
        'persona_identity_delete')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Create credential. Payload: JSON with identity_id, name, credential_type, security_level, credential_data.
late final _personaCredentialCreate = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> payload)>>(
        'persona_credential_create')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// List credentials for an identity (metadata only, no decrypted payload).
late final _personaCredentialList = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> identityId)>>(
        'persona_credential_list')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Get decrypted credential data (sensitive op, requires unlocked).
late final _personaCredentialData = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> credentialId)>>(
        'persona_credential_data')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Delete credential.
late final _personaCredentialDelete = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> credentialId)>>(
        'persona_credential_delete')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Search credentials by query string (metadata only).
late final _personaCredentialSearch = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> query)>>(
        'persona_credential_search')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

/// Generate TOTP code for a TwoFactor/GameToken credential.
/// Returns JSON { ok: true, data: { code, remaining_seconds, period, digits, algorithm, issuer, account_name } }.
late final _personaTotpCode = _personaLib
    .lookup<
        NativeFunction<Pointer<Utf8> Function(Pointer<Utf8> credentialId)>>(
        'persona_totp_code')
    .asFunction<Pointer<Utf8> Function(Pointer<Utf8>)>();

// -----------------------------------------------------------------------------
// Dart-friendly wrappers
// -----------------------------------------------------------------------------

String _resultError(PersonaResult r) {
  if (r.errorMessage == nullptr) return 'Unknown error';
  final msg = r.errorMessage.toDartString();
  _personaFreeResult(r);
  return msg;
}

void _checkResult(PersonaResult r, String context) {
  if (r.success == 0) {
    throw PersonaException(_resultError(r), context: context);
  }
  _personaFreeResult(r);
}

String _callJson(Pointer<Utf8> Function() call, String context) {
  final ptr = call();
  if (ptr == nullptr) throw PersonaException('Null pointer from FFI', context: context);
  try {
    final json = ptr.toDartString();
    return json;
  } finally {
    _personaFreeString(ptr);
  }
}

String _callJsonArg(Pointer<Utf8> Function(Pointer<Utf8>) call, String arg, String context) {
  final argPtr = arg.toNativeUtf8();
  try {
    final ptr = call(argPtr);
    if (ptr == nullptr) throw PersonaException('Null pointer from FFI', context: context);
    final json = ptr.toDartString();
    return json;
  } finally {
    _personaFreeString(argPtr);
  }
}

String _callJsonTwoArgs(
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) call,
    String arg1,
    String arg2,
    String context) {
  final a1 = arg1.toNativeUtf8();
  final a2 = arg2.toNativeUtf8();
  try {
    final ptr = call(a1, a2);
    if (ptr == nullptr) throw PersonaException('Null pointer from FFI', context: context);
    final json = ptr.toDartString();
    return json;
  } finally {
    _personaFreeString(a1);
    _personaFreeString(a2);
  }
}

/// Exception thrown by Persona FFI calls.
class PersonaException implements Exception {
  final String message;
  final String context;

  PersonaException(this.message, {required this.context});

  @override
  String toString() => 'PersonaException($context): $message';
}

/// High-level API matching the Rust FFI surface.
class PersonaApi {
  /// Initialize library (no-op currently, returns 0).
  static int init() => _personaInit();

  /// Get library version. Returns 'unknown' when the native library
  /// is unavailable (e.g. in widget tests).
  static String version() {
    try {
      final ptr = _personaVersion();
      if (ptr == nullptr) return 'unknown';
      try {
        return ptr.toDartString();
      } finally {
        _personaFreeString(ptr);
      }
    } catch (_) {
      return 'unknown';
    }
  }

  /// Initialize service (create user or authenticate). Returns on success.
  static Future<void> serviceInit({
    required String dbPath,
    required String masterPassword,
  }) async {
    final r = _personaServiceInit(dbPath.toNativeUtf8(), masterPassword.toNativeUtf8());
    _checkResult(r, 'serviceInit');
  }

  /// Unlock with master password.
  static Future<void> serviceUnlock(String masterPassword) async {
    final r = _personaServiceUnlock(masterPassword.toNativeUtf8());
    _checkResult(r, 'serviceUnlock');
  }

  /// Lock session.
  static Future<void> serviceLock() async {
    final r = _personaServiceLock();
    _checkResult(r, 'serviceLock');
  }

  /// Check if unlocked.
  static bool serviceIsUnlocked() => _personaServiceIsUnlocked() != 0;

  /// Configure sync emitter. Both non-empty to enable; either blank to disable.
  static Future<void> configureSync({
    required String serverUrl,
    required String token,
  }) async {
    final r = _personaConfigureSync(serverUrl.toNativeUtf8(), token.toNativeUtf8());
    _checkResult(r, 'configureSync');
  }

  /// Shutdown service and emitter.
  static Future<void> shutdown() async {
    final r = _personaShutdown();
    _checkResult(r, 'shutdown');
  }

  // --- Business API (JSON envelopes) ---

  static Future<Map<String, dynamic>> identityCreate({
    required String name,
    required String identityType,
    String? description,
    String? email,
    String? phone,
  }) async {
    final payload = {
      'name': name,
      'identity_type': identityType,
      if (description != null) 'description': description,
      if (email != null) 'email': email,
      if (phone != null) 'phone': phone,
    };
    final json = _callJsonArg(_personaIdentityCreate, jsonEncode(payload), 'identityCreate');
    return jsonDecode(json) as Map<String, dynamic>;
  }

  static Future<List<dynamic>> identityList() async {
    final json = _callJson(_personaIdentityList, 'identityList');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as List<dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'identityList');
  }

  static Future<Map<String, dynamic>?> identityGet(String id) async {
    final json = _callJsonArg(_personaIdentityGet, id, 'identityGet');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) {
      final data = map['data'];
      if (data == null) return null;
      return data as Map<String, dynamic>;
    }
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'identityGet');
  }

  static Future<Map<String, dynamic>> identityUpdate(Map<String, dynamic> identity) async {
    final json = _callJsonArg(_personaIdentityUpdate, jsonEncode(identity), 'identityUpdate');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as Map<String, dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'identityUpdate');
  }

  static Future<bool> identityDelete(String id) async {
    final json = _callJsonArg(_personaIdentityDelete, id, 'identityDelete');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as bool;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'identityDelete');
  }

  static Future<Map<String, dynamic>> credentialCreate({
    required String identityId,
    required String name,
    required String credentialType,
    required String securityLevel,
    required Map<String, dynamic> credentialData,
  }) async {
    final payload = {
      'identity_id': identityId,
      'name': name,
      'credential_type': credentialType,
      'security_level': securityLevel,
      'credential_data': credentialData,
    };
    final json = _callJsonArg(_personaCredentialCreate, jsonEncode(payload), 'credentialCreate');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as Map<String, dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'credentialCreate');
  }

  static Future<List<dynamic>> credentialList(String identityId) async {
    final json = _callJsonArg(_personaCredentialList, identityId, 'credentialList');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as List<dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'credentialList');
  }

  static Future<Map<String, dynamic>?> credentialData(String credentialId) async {
    final json = _callJsonArg(_personaCredentialData, credentialId, 'credentialData');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) {
      final data = map['data'];
      if (data == null) return null;
      return data as Map<String, dynamic>;
    }
    if (map['error'] == 'Credential not found') return null;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'credentialData');
  }

  static Future<bool> credentialDelete(String credentialId) async {
    final json = _callJsonArg(_personaCredentialDelete, credentialId, 'credentialDelete');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as bool;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'credentialDelete');
  }

  static Future<List<dynamic>> credentialSearch(String query) async {
    final json = _callJsonArg(_personaCredentialSearch, query, 'credentialSearch');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as List<dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'credentialSearch');
  }

  static Future<Map<String, dynamic>> totpCode(String credentialId) async {
    final json = _callJsonArg(_personaTotpCode, credentialId, 'totpCode');
    final map = jsonDecode(json) as Map<String, dynamic>;
    if (map['ok'] == true) return map['data'] as Map<String, dynamic>;
    throw PersonaException(map['error'] as String? ?? 'Unknown error', context: 'totpCode');
  }
}