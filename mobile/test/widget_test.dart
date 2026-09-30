import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:persona_mobile/main.dart';
import 'package:persona_mobile/src/state/app_state.dart';
import 'package:persona_mobile/src/ui/unlock_screen.dart';
import 'package:persona_mobile/src/ui/credential_list_screen.dart';
import 'package:persona_mobile/src/ui/credential_detail_screen.dart';

void main() {
  group('PersonaApp', () {
    testWidgets('renders unlock screen on first launch', (tester) async {
      await tester.pumpWidget(const PersonaApp());
      await tester.pumpAndSettle();
      expect(find.text('Create Vault'), findsWidgets);
    });
  });

  group('UnlockScreen', () {
    testWidgets('first launch shows create vault form', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: UnlockScreen(isFirstLaunch: true)),
      );
      await tester.pumpAndSettle();
      expect(find.text('Create Vault'), findsWidgets);
      expect(find.text('Confirm Password'), findsOneWidget);
    });

    testWidgets('subsequent launch shows unlock form', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: UnlockScreen(isFirstLaunch: false)),
      );
      await tester.pumpAndSettle();
      expect(find.text('Unlock Vault'), findsOneWidget);
      expect(find.text('Confirm Password'), findsNothing);
    });
  });

  group('CredentialListScreen', () {
    testWidgets('renders credential list', (tester) async {
      final appState = AppState();
      await tester.pumpWidget(
        ChangeNotifierProvider<AppState>.value(
          value: appState,
          child: const MaterialApp(
            home: CredentialListScreen(
              identityId: 'id-1',
              identityName: 'Personal',
              searchQuery: '',
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      // Empty state
      expect(find.text('No credentials yet'), findsOneWidget);
    });
  });

  group('CredentialDetailScreen', () {
    testWidgets('renders detail for password credential', (tester) async {
      final appState = AppState();
      await tester.pumpWidget(
        ChangeNotifierProvider<AppState>.value(
          value: appState,
          child: MaterialApp(
            home: CredentialDetailScreen(
              credential: const {
                'id': 'c-1',
                'name': 'GitHub',
                'credential_type': 'Password',
                'security_level': 'High',
              },
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      // FFI unavailable in tests → error state shown
      expect(find.text('GitHub'), findsOneWidget);
      expect(find.text('Failed to decrypt credential'), findsOneWidget);
    });
  });
}
