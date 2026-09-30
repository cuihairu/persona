/// 手写 dart:ffi 绑定：对接 mobile/rust 的 extern "C" 宿主接线。
///
/// 契约（见 mobile/rust/src/lib.rs）：
/// - 生命周期函数返回 `PersonaResult`（repr(C)：success + error_message），
///   由 `persona_free_result` 归还；
/// - 业务函数返回 JSON 字符串 envelope `{ok, data|error}`，由
///   `persona_free_string` 归还；
/// - 服务状态留 Rust 侧全局槽位，指针仅限入参借用。
///
/// 所有调用经 `Isolate.run` 进后台 isolate：Rust 侧 `runtime::block_on`
/// 是阻塞调用（解锁含 Argon2，秒级），不能占主 isolate。闭包只捕获
/// 可传输的 String，FFI lookup 一律在 isolate 内的顶层函数里现查
/// （闭包不能捕获本类实例——对象不可跨 isolate 发送）。
library;

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:isolate';

import 'package:ffi/ffi.dart';

/// 抽象接口：UI 依赖此层注入，测试传 fake。
abstract class PersonaApi {
  /// 打开/迁移 vault 并建户（首次）或认证（既有用户）；成功即解锁态。
  Future<void> initVault(String dbPath, String masterPassword);

  /// 用主密码解锁已初始化但未解锁的会话。
  Future<void> unlock(String masterPassword);

  /// 立即落锁（清内存主密钥）。
  Future<void> lock();

  /// 身份列表（id/name/identity_type/…）。
  Future<List<Map<String, dynamic>>> listIdentities();

  /// 某身份的凭据元数据列表。
  Future<List<Map<String, dynamic>>> listCredentials(String identityId);

  /// 凭据全文搜索（名称/用户名/URL 等元数据）。
  Future<List<Map<String, dynamic>>> searchCredentials(String query);
}

/// 生产实现：绑定 libpersona_mobile.so。
class PersonaFfiApi implements PersonaApi {
  PersonaFfiApi();

  @override
  Future<void> initVault(String dbPath, String masterPassword) =>
      Isolate.run(() => _initVault(dbPath, masterPassword));

  @override
  Future<void> unlock(String masterPassword) =>
      Isolate.run(() => _unlock(masterPassword));

  @override
  Future<void> lock() => Isolate.run(_lock);

  @override
  Future<List<Map<String, dynamic>>> listIdentities() =>
      Isolate.run(_listIdentities);

  @override
  Future<List<Map<String, dynamic>>> listCredentials(String identityId) =>
      Isolate.run(() => _listCredentials(identityId));

  @override
  Future<List<Map<String, dynamic>>> searchCredentials(String query) =>
      Isolate.run(() => _searchCredentials(query));
}

/// `#[repr(C)] struct PersonaResult { success: bool, error_message: *mut c_char }`
/// 的 Dart 镜像（字段顺序/对齐按 C ABI）。
final class PersonaResultStruct extends ffi.Struct {
  @ffi.Bool()
  external bool success;

  external ffi.Pointer<Utf8> errorMessage;
}

// ---------------------------------------------------------------------------
// 顶层 FFI 实现（在 Isolate.run 的 isolate 内执行）
// ---------------------------------------------------------------------------

ffi.DynamicLibrary _openLib() {
  try {
    return ffi.DynamicLibrary.open('libpersona_mobile.so');
  } on ArgumentError catch (e) {
    throw StateError('无法加载 libpersona_mobile.so：${e.message}');
  }
}

void _initVault(String dbPath, String masterPassword) {
  final lib = _openLib();
  final init = lib.lookupFunction<
      PersonaResultStruct Function(ffi.Pointer<Utf8>, ffi.Pointer<Utf8>),
      PersonaResultStruct Function(
          ffi.Pointer<Utf8>, ffi.Pointer<Utf8>)>('persona_service_init');
  final freeResult = lib.lookupFunction<ffi.Void Function(PersonaResultStruct),
      void Function(PersonaResultStruct)>('persona_free_result');
  final db = dbPath.toNativeUtf8();
  final pw = masterPassword.toNativeUtf8();
  try {
    final result = init(db, pw);
    _rethrowResult(result, freeResult);
  } finally {
    calloc.free(db);
    calloc.free(pw);
  }
}

void _unlock(String masterPassword) {
  final lib = _openLib();
  final unlock = lib.lookupFunction<
      PersonaResultStruct Function(ffi.Pointer<Utf8>),
      PersonaResultStruct Function(
          ffi.Pointer<Utf8>)>('persona_service_unlock');
  final freeResult = lib.lookupFunction<ffi.Void Function(PersonaResultStruct),
      void Function(PersonaResultStruct)>('persona_free_result');
  final pw = masterPassword.toNativeUtf8();
  try {
    final result = unlock(pw);
    _rethrowResult(result, freeResult);
  } finally {
    calloc.free(pw);
  }
}

void _lock() {
  final lib = _openLib();
  final lock = lib.lookupFunction<PersonaResultStruct Function(),
      PersonaResultStruct Function()>('persona_service_lock');
  final freeResult = lib.lookupFunction<ffi.Void Function(PersonaResultStruct),
      void Function(PersonaResultStruct)>('persona_free_result');
  _rethrowResult(lock(), freeResult);
}

List<Map<String, dynamic>> _listIdentities() {
  final lib = _openLib();
  final list = lib.lookupFunction<ffi.Pointer<Utf8> Function(),
      ffi.Pointer<Utf8> Function()>('persona_identity_list');
  final freeString =
      lib.lookupFunction<ffi.Void Function(ffi.Pointer<Utf8>),
          void Function(ffi.Pointer<Utf8>)>('persona_free_string');
  return _envelopeToList(list(), freeString);
}

List<Map<String, dynamic>> _listCredentials(String identityId) {
  final lib = _openLib();
  final list = lib.lookupFunction<
      ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8>),
      ffi.Pointer<Utf8> Function(
          ffi.Pointer<Utf8>)>('persona_credential_list');
  final freeString = lib.lookupFunction<ffi.Void Function(ffi.Pointer<Utf8>),
      void Function(ffi.Pointer<Utf8>)>('persona_free_string');
  final id = identityId.toNativeUtf8();
  try {
    return _envelopeToList(list(id), freeString);
  } finally {
    calloc.free(id);
  }
}

List<Map<String, dynamic>> _searchCredentials(String query) {
  final lib = _openLib();
  final search = lib.lookupFunction<
      ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8>),
      ffi.Pointer<Utf8> Function(
          ffi.Pointer<Utf8>)>('persona_credential_search');
  final freeString = lib.lookupFunction<ffi.Void Function(ffi.Pointer<Utf8>),
      void Function(ffi.Pointer<Utf8>)>('persona_free_string');
  final q = query.toNativeUtf8();
  try {
    return _envelopeToList(search(q), freeString);
  } finally {
    calloc.free(q);
  }
}

/// PersonaResult 失败即抛 StateError；成功时经 freeResult 归还结构
/// （error_message 为 null，归还仍必须执行——由调用方在 finally 外
/// 的这条路径统一处理）。
void _rethrowResult(
  PersonaResultStruct result,
  void Function(PersonaResultStruct) freeResult,
) {
  final messagePtr = result.errorMessage;
  final error = result.success
      ? null
      : (messagePtr == ffi.nullptr ? '未知错误' : messagePtr.toDartString());
  freeResult(result);
  if (error != null) {
    throw StateError(error);
  }
}

/// 业务 envelope 字符串 → 列表；`{ok:false, error}` 抛 StateError。
List<Map<String, dynamic>> _envelopeToList(
  ffi.Pointer<Utf8> ptr,
  void Function(ffi.Pointer<Utf8>) freeString,
) {
  if (ptr == ffi.nullptr) {
    throw StateError('FFI 返回空指针');
  }
  final jsonStr = ptr.toDartString();
  freeString(ptr);
  final decoded = jsonDecode(jsonStr);
  if (decoded is! Map<String, dynamic> || decoded['ok'] != true) {
    final err = decoded is Map<String, dynamic> ? decoded['error'] : '格式错误';
    throw StateError('$err');
  }
  final data = decoded['data'];
  if (data is! List) {
    throw StateError('envelope data 不是列表');
  }
  return data.map((e) => e as Map<String, dynamic>).toList();
}
