import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'persona_mobile.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PersonaApp());
}

class PersonaApp extends StatelessWidget {
  const PersonaApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => AppState()..loadPersisted(),
      child: MaterialApp(
        title: 'Persona Mobile',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          useMaterial3: true,
          colorSchemeSeed: const Color(0xFF006E7F), // Persona teal
          brightness: Brightness.light,
        ),
        darkTheme: ThemeData(
          useMaterial3: true,
          colorSchemeSeed: const Color(0xFF006E7F),
          brightness: Brightness.dark,
        ),
        themeMode: ThemeMode.system,
        initialRoute: '/unlock',
        routes: {
          '/unlock': (context) => Consumer<AppState>(
                builder: (_, appState, __) => UnlockScreen(
                  isFirstLaunch: !appState.hasVault,
                ),
              ),
          '/main': (context) => const MainScreen(),
        },
      ),
    );
  }
}