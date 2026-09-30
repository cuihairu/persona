/// Global app state (ChangeNotifier) wrapping PersonaApi lifecycle and cached data.
///
/// Single vault, single user. Mirrors desktop's AppState but minimal for mobile.
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import '../ffi/persona_bindings.dart';

class AppState extends ChangeNotifier {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );

  static const _kDbPathKey = 'persona.db_path';
  static const _kSyncUrlKey = 'persona.sync_url';
  static const _kSyncTokenKey = 'persona.sync_token';
  static const _kHasVaultKey = 'persona.has_vault';

  bool _initialized = false;
  bool _unlocked = false;
  String? _masterPassword; // kept only while unlocked (cleared on lock)
  String? _syncUrl;
  String? _syncToken;
  List<dynamic> _identities = [];
  Map<String, List<dynamic>> _credentialsByIdentity = {};
  String? _currentIdentityId;

  bool get initialized => _initialized;
  bool get unlocked => _unlocked;
  bool get hasVault => _initialized;
  List<dynamic> get identities => _identities;
  Map<String, List<dynamic>> get credentialsByIdentity => _credentialsByIdentity;
  String? get currentIdentityId => _currentIdentityId;
  String? get syncUrl => _syncUrl;
  String? get syncToken => _syncToken;

  /// Initialize from secure storage on app start.
  Future<void> loadPersisted() async {
    final dbPath = await _storage.read(key: _kDbPathKey);
    final syncUrl = await _storage.read(key: _kSyncUrlKey);
    final syncToken = await _storage.read(key: _kSyncTokenKey);
    final hasVault = await _storage.read(key: _kHasVaultKey);

    if (dbPath != null && hasVault == 'true') {
      _syncUrl = syncUrl;
      _syncToken = syncToken;
      // Don't auto-unlock; wait for user to enter master password.
      // But we can configure sync if both present.
      if (syncUrl != null && syncUrl.isNotEmpty && syncToken != null && syncToken.isNotEmpty) {
        await PersonaApi.configureSync(serverUrl: syncUrl, token: syncToken);
      }
      _initialized = true;
      notifyListeners();
    }
  }

  /// Get or create the vault database path.
  Future<String> _getDbPath() async {
    String? dbPath = await _storage.read(key: _kDbPathKey);
    if (dbPath != null) return dbPath;

    final dir = await getApplicationDocumentsDirectory();
    dbPath = '${dir.path}/persona.db';
    await _storage.write(key: _kDbPathKey, value: dbPath);
    await _storage.write(key: _kHasVaultKey, value: 'true');
    return dbPath;
  }

  /// First-time setup: create vault and user with master password.
  Future<void> createVault(String masterPassword) async {
    final dbPath = await _getDbPath();
    await PersonaApi.serviceInit(dbPath: dbPath, masterPassword: masterPassword);
    _masterPassword = masterPassword;
    _unlocked = true;
    await _refreshIdentities();
    notifyListeners();
  }

  /// Unlock existing vault.
  Future<void> unlock(String masterPassword) async {
    await PersonaApi.serviceUnlock(masterPassword);
    _masterPassword = masterPassword;
    _unlocked = true;
    await _refreshIdentities();
    notifyListeners();
  }

  /// Lock vault (clear in-memory keys).
  Future<void> lock() async {
    await PersonaApi.serviceLock();
    _masterPassword = null;
    _unlocked = false;
    _credentialsByIdentity.clear();
    notifyListeners();
  }

  /// Configure sync (called after unlock or on init if credentials exist).
  Future<void> setSyncConfig({required String url, required String token}) async {
    await PersonaApi.configureSync(serverUrl: url, token: token);
    _syncUrl = url;
    _syncToken = token;
    await _storage.write(key: _kSyncUrlKey, value: url);
    await _storage.write(key: _kSyncTokenKey, value: token);
  }

  /// Disable sync.
  Future<void> disableSync() async {
    await PersonaApi.configureSync(serverUrl: '', token: '');
    _syncUrl = null;
    _syncToken = null;
    await _storage.delete(key: _kSyncUrlKey);
    await _storage.delete(key: _kSyncTokenKey);
  }

  Future<void> _refreshIdentities() async {
    _identities = await PersonaApi.identityList();
    // Pick first identity as current if none selected
    if (_identities.isNotEmpty && _currentIdentityId == null) {
      _currentIdentityId = _identities.first['id'] as String?;
    }
    // Preload credentials for current identity
    if (_currentIdentityId != null) {
      await _loadCredentials(_currentIdentityId!);
    }
  }

  Future<void> _loadCredentials(String identityId) async {
    final creds = await PersonaApi.credentialList(identityId);
    _credentialsByIdentity[identityId] = creds;
  }

  List<dynamic> getCredentials(String identityId) {
    return _credentialsByIdentity[identityId] ?? [];
  }

  Future<void> refreshCredentials(String identityId) async {
    await _loadCredentials(identityId);
    notifyListeners();
  }

  void setCurrentIdentity(String identityId) {
    _currentIdentityId = identityId;
    if (!_credentialsByIdentity.containsKey(identityId)) {
      _loadCredentials(identityId);
    }
    notifyListeners();
  }

  /// Create a new identity and select it.
  Future<void> createIdentity({
    required String name,
    required String identityType,
    String? description,
    String? email,
    String? phone,
  }) async {
    final result = await PersonaApi.identityCreate(
      name: name,
      identityType: identityType,
      description: description,
      email: email,
      phone: phone,
    );
    await _refreshIdentities();
    if (result['id'] != null) {
      setCurrentIdentity(result['id'] as String);
    }
  }

  /// Create a credential under current identity.
  Future<void> createCredential({
    required String name,
    required String credentialType,
    required String securityLevel,
    required Map<String, dynamic> credentialData,
  }) async {
    if (_currentIdentityId == null) throw StateError('No identity selected');
    await PersonaApi.credentialCreate(
      identityId: _currentIdentityId!,
      name: name,
      credentialType: credentialType,
      securityLevel: securityLevel,
      credentialData: credentialData,
    );
    await refreshCredentials(_currentIdentityId!);
  }

  /// Get decrypted credential data.
  Future<Map<String, dynamic>?> getCredentialData(String credentialId) async {
    return await PersonaApi.credentialData(credentialId);
  }

  /// Delete credential.
  Future<void> deleteCredential(String credentialId) async {
    if (_currentIdentityId == null) return;
    await PersonaApi.credentialDelete(credentialId);
    await refreshCredentials(_currentIdentityId!);
  }

  /// Search credentials across all identities.
  Future<List<dynamic>> searchCredentials(String query) async {
    return await PersonaApi.credentialSearch(query);
  }

  /// Generate TOTP code.
  Future<Map<String, dynamic>> generateTotp(String credentialId) async {
    return await PersonaApi.totpCode(credentialId);
  }

  /// Shutdown (app termination).
  Future<void> shutdown() async {
    await PersonaApi.shutdown();
    _masterPassword = null;
    _unlocked = false;
    _initialized = false;
    _identities.clear();
    _credentialsByIdentity.clear();
    _currentIdentityId = null;
  }
}