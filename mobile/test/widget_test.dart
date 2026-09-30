import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:persona_mobile/ffi/persona_ffi.dart';
import 'package:persona_mobile/main.dart';

/// 内存 fake：记录调用轨迹，数据可编排，不碰 FFI。
class FakeApi implements PersonaApi {
  FakeApi({
    this.identities = const [
      {'id': 'id-1', 'name': '个人'},
      {'id': 'id-2', 'name': '工作'},
    ],
    this.credentialsByIdentity = const {
      'id-1': [
        {
          'id': 'c-1',
          'name': 'GitHub',
          'credential_type': 'Password',
          'username': 'alice',
          'url': 'https://github.com',
        },
        {
          'id': 'c-2',
          'name': '公司邮箱',
          'credential_type': 'Password',
          'username': 'alice@corp.example.com',
        },
      ],
      'id-2': [
        {
          'id': 'c-3',
          'name': '部署密钥',
          'credential_type': 'ApiKey',
        },
      ],
    },
    this.searchResults = const [
      {
        'id': 'c-1',
        'name': 'GitHub',
        'credential_type': 'Password',
        'username': 'alice',
        'url': 'https://github.com',
      },
    ],
    this.initError,
  });

  final List<Map<String, dynamic>> identities;
  final Map<String, List<Map<String, dynamic>>> credentialsByIdentity;
  final List<Map<String, dynamic>> searchResults;
  final Object? initError;

  final List<String> calls = [];
  bool locked = false;
  String? lastPassword;

  @override
  Future<void> initVault(String dbPath, String masterPassword) async {
    calls.add('init');
    lastPassword = masterPassword;
    if (initError != null) {
      throw initError!;
    }
  }

  @override
  Future<void> unlock(String masterPassword) async {
    calls.add('unlock');
    lastPassword = masterPassword;
    if (initError != null) {
      throw initError!;
    }
  }

  @override
  Future<void> lock() async {
    calls.add('lock');
    locked = true;
  }

  @override
  Future<List<Map<String, dynamic>>> listIdentities() async {
    calls.add('listIdentities');
    return identities;
  }

  @override
  Future<List<Map<String, dynamic>>> listCredentials(String identityId) async {
    calls.add('listCredentials:$identityId');
    return credentialsByIdentity[identityId] ?? [];
  }

  @override
  Future<List<Map<String, dynamic>>> searchCredentials(String query) async {
    calls.add('search:$query');
    return searchResults;
  }
}

Widget _app(PersonaApi api) => PersonaApp(api: api, dbPath: '/tmp/fake.db');

Future<void> _unlockScene(WidgetTester tester, FakeApi api) async {
  await tester.pumpWidget(_app(api));
  await tester.pumpAndSettle();
  await tester.enterText(find.byType(TextField), 'correct horse');
  await tester.tap(find.widgetWithText(FilledButton, '解锁'));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('首次解锁 → 建库入参被调用，进入列表', (tester) async {
    final api = FakeApi();
    await _unlockScene(tester, api);

    expect(api.calls, contains('init'));
    // 密码提交后输入框立即清空（不驻留 UI 内存）
    expect(find.widgetWithText(TextField, ''), findsOneWidget);
    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('公司邮箱'), findsOneWidget);
    // 默认选中第一个身份并拉取其凭据
    expect(api.calls, contains('listCredentials:id-1'));
    // 类型标签本地化
    expect(find.text('密码'), findsWidgets);
  });

  testWidgets('解锁失败显示错误且留在解锁页', (tester) async {
    final api = FakeApi(initError: StateError('Invalid master password'));
    await tester.pumpWidget(_app(api));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'wrong');
    await tester.tap(find.widgetWithText(FilledButton, '解锁'));
    await tester.pumpAndSettle();

    expect(find.textContaining('Invalid master password'), findsOneWidget);
    expect(find.text('Persona'), findsWidgets);
    expect(api.locked, isFalse);
  });

  testWidgets('搜索走 searchCredentials 且展示结果', (tester) async {
    final api = FakeApi();
    await _unlockScene(tester, api);
    expect(find.text('部署密钥'), findsNothing); // id-1 初始列表

    await tester.enterText(find.byType(TextField), 'github');
    await tester.pump(const Duration(milliseconds: 400)); // debounce
    await tester.pumpAndSettle();

    expect(api.calls, contains('search:github'));
    expect(find.text('GitHub'), findsOneWidget);
  });

  testWidgets('切换身份重新拉取该身份凭据', (tester) async {
    final api = FakeApi();
    await _unlockScene(tester, api);
    expect(find.text('部署密钥'), findsNothing);

    await tester.tap(find.byType(DropdownButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('工作').last);
    await tester.pumpAndSettle();

    expect(api.calls, contains('listCredentials:id-2'));
    expect(find.text('部署密钥'), findsOneWidget);
  });

  testWidgets('锁定调用 api.lock 并回到解锁页', (tester) async {
    final api = FakeApi();
    await _unlockScene(tester, api);

    await tester.tap(find.byIcon(Icons.lock_outline));
    await tester.pumpAndSettle();

    expect(api.calls, contains('lock'));
    expect(api.locked, isTrue);
    expect(find.widgetWithText(FilledButton, '解锁'), findsOneWidget);
  });
}
