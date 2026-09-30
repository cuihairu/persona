/// Main screen after unlock: identity switcher + credential list + search.
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';
import 'credential_list_screen.dart';
import 'search_delegate.dart';

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  String _searchQuery = '';

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) {
        if (!appState.unlocked) {
          return const Scaffold(body: Center(child: CircularProgressIndicator()));
        }

        final currentId = appState.currentIdentityId;
        final currentIdentity = currentId != null
            ? appState.identities.firstWhere(
                (i) => i['id'] == currentId,
                orElse: () => null,
              )
            : null;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Persona'),
            actions: [
              // Identity switcher
              if (appState.identities.isNotEmpty)
                PopupMenuButton<String>(
                  initialValue: currentId,
                  onSelected: (id) => appState.setCurrentIdentity(id),
                  itemBuilder: (context) => appState.identities.map((i) {
                    return PopupMenuItem<String>(
                      value: i['id'] as String,
                      child: Row(
                        children: [
                          Icon(_iconForType(i['identity_type']), size: 20),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(i['name'] as String, overflow: TextOverflow.ellipsis),
                          ),
                        ],
                      ),
                    );
                  }).toList(),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: Row(
                      children: [
                        if (currentIdentity != null)
                          Icon(_iconForType(currentIdentity['identity_type']), size: 20),
                        if (currentIdentity != null) const SizedBox(width: 8),
                        Text(currentIdentity?['name'] as String? ?? 'Identity'),
                        const Icon(Icons.arrow_drop_down),
                      ],
                    ),
                  ),
                ),
              // Search
              IconButton(
                icon: const Icon(Icons.search),
                onPressed: () => showSearch(context: context, delegate: PersonaSearchDelegate()),
              ),
              // Lock
              IconButton(
                icon: const Icon(Icons.lock_outline),
                onPressed: () => _confirmLock(context, appState),
              ),
            ],
          ),
          body: currentId == null
              ? _EmptyState(onCreate: () => _showCreateIdentityDialog(context, appState))
              : CredentialListScreen(
                  identityId: currentId,
                  identityName: currentIdentity?['name'] as String? ?? 'Identity',
                  searchQuery: _searchQuery,
                ),
          floatingActionButton: currentId != null
              ? FloatingActionButton(
                  onPressed: () => _showCreateCredentialDialog(context, appState),
                  child: const Icon(Icons.add),
                )
              : null,
        );
      },
    );
  }

  IconData _iconForType(dynamic type) {
    if (type is String) {
      switch (type) {
        case 'Personal':
          return Icons.person_outline;
        case 'Work':
          return Icons.work_outline;
        case 'Social':
          return Icons.groups;
        case 'Financial':
          return Icons.account_balance_outlined;
        case 'Gaming':
          return Icons.sports_esports_outlined;
        default:
          return Icons.label_outline;
      }
    }
    if (type is Map && type.containsKey('Custom')) {
      return Icons.label_outline;
    }
    return Icons.label_outline;
  }

  Future<void> _confirmLock(BuildContext context, AppState appState) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Lock Vault?'),
        content: const Text('This will clear the master password from memory.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Lock')),
        ],
      ),
    );
    if (confirm == true) {
      await appState.lock();
      if (mounted) {
        Navigator.of(context).pushNamedAndRemoveUntil('/unlock', (route) => false);
      }
    }
  }

  void _showCreateIdentityDialog(BuildContext context, AppState appState) {
    final nameCtrl = TextEditingController();
    String type = 'Personal';
    final descCtrl = TextEditingController();
    final emailCtrl = TextEditingController();
    final phoneCtrl = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Create Identity'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameCtrl,
                decoration: const InputDecoration(labelText: 'Name *'),
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                value: type,
                decoration: const InputDecoration(labelText: 'Type'),
                items: const [
                  DropdownMenuItem(value: 'Personal', child: Text('Personal')),
                  DropdownMenuItem(value: 'Work', child: Text('Work')),
                  DropdownMenuItem(value: 'Social', child: Text('Social')),
                  DropdownMenuItem(value: 'Financial', child: Text('Financial')),
                  DropdownMenuItem(value: 'Gaming', child: Text('Gaming')),
                  DropdownMenuItem(value: 'Custom', child: Text('Custom')),
                ],
                onChanged: (v) => type = v!,
              ),
              const SizedBox(height: 12),
              TextField(controller: descCtrl, decoration: const InputDecoration(labelText: 'Description')),
              const SizedBox(height: 12),
              TextField(controller: emailCtrl, decoration: const InputDecoration(labelText: 'Email')),
              const SizedBox(height: 12),
              TextField(controller: phoneCtrl, decoration: const InputDecoration(labelText: 'Phone')),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () async {
              if (nameCtrl.text.isEmpty) return;
              Navigator.pop(ctx);
              await appState.createIdentity(
                name: nameCtrl.text,
                identityType: type,
                description: descCtrl.text.isEmpty ? null : descCtrl.text,
                email: emailCtrl.text.isEmpty ? null : emailCtrl.text,
                phone: phoneCtrl.text.isEmpty ? null : phoneCtrl.text,
              );
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }

  void _showCreateCredentialDialog(BuildContext context, AppState appState) {
    final nameCtrl = TextEditingController();
    String credType = 'Password';
    String secLevel = 'High';
    final usernameCtrl = TextEditingController();
    final passwordCtrl = TextEditingController();
    final urlCtrl = TextEditingController();
    final notesCtrl = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Credential'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(controller: nameCtrl, decoration: const InputDecoration(labelText: 'Name *')),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                value: credType,
                decoration: const InputDecoration(labelText: 'Type'),
                items: const [
                  DropdownMenuItem(value: 'Password', child: Text('Password')),
                  DropdownMenuItem(value: 'TwoFactor', child: Text('Two-Factor (TOTP)')),
                  DropdownMenuItem(value: 'GameToken', child: Text('Game Token')),
                  DropdownMenuItem(value: 'Passkey', child: Text('Passkey')),
                  DropdownMenuItem(value: 'SecureNote', child: Text('Secure Note')),
                ],
                onChanged: (v) => credType = v!,
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                value: secLevel,
                decoration: const InputDecoration(labelText: 'Security Level'),
                items: const [
                  DropdownMenuItem(value: 'Low', child: Text('Low')),
                  DropdownMenuItem(value: 'Medium', child: Text('Medium')),
                  DropdownMenuItem(value: 'High', child: Text('High')),
                  DropdownMenuItem(value: 'Critical', child: Text('Critical')),
                ],
                onChanged: (v) => secLevel = v!,
              ),
              const SizedBox(height: 12),
              if (credType == 'Password' || credType == 'TwoFactor' || credType == 'GameToken') ...[
                TextField(controller: usernameCtrl, decoration: const InputDecoration(labelText: 'Username / Account')),
                const SizedBox(height: 12),
              ],
              if (credType == 'Password') ...[
                TextField(
                  controller: passwordCtrl,
                  decoration: const InputDecoration(labelText: 'Password *'),
                  obscureText: true,
                ),
                const SizedBox(height: 12),
              ],
              if (credType == 'TwoFactor') ...[
                TextField(
                  controller: passwordCtrl,
                  decoration: const InputDecoration(labelText: 'TOTP Secret (base32) *'),
                ),
                const SizedBox(height: 12),
                TextField(controller: urlCtrl, decoration: const InputDecoration(labelText: 'Issuer')),
                const SizedBox(height: 12),
              ],
              if (credType == 'GameToken') ...[
                TextField(
                  controller: passwordCtrl,
                  decoration: const InputDecoration(labelText: 'Shared Secret (base64) *'),
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  value: 'steam_guard',
                  decoration: const InputDecoration(labelText: 'Provider'),
                  items: const [
                    DropdownMenuItem(value: 'steam_guard', child: Text('Steam Guard')),
                  ],
                  onChanged: (v) {},
                ),
                const SizedBox(height: 12),
              ],
              if (credType == 'SecureNote') ...[
                TextField(
                  controller: notesCtrl,
                  decoration: const InputDecoration(labelText: 'Note *'),
                  maxLines: 4,
                ),
                const SizedBox(height: 12),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () async {
              if (nameCtrl.text.isEmpty) return;

              Map<String, dynamic> credData = {};
              switch (credType) {
                case 'Password':
                  if (passwordCtrl.text.isEmpty) return;
                  credData = {
                    'Password': {
                      'password': passwordCtrl.text,
                      'email': usernameCtrl.text,
                      'security_questions': [],
                    }
                  };
                  break;
                case 'TwoFactor':
                  if (passwordCtrl.text.isEmpty) return;
                  credData = {
                    'TwoFactor': {
                      'secret_key': passwordCtrl.text,
                      'issuer': urlCtrl.text.isEmpty ? 'Persona' : urlCtrl.text,
                      'account_name': usernameCtrl.text,
                      'algorithm': 'SHA1',
                      'digits': 6,
                      'period': 30,
                    }
                  };
                  break;
                case 'GameToken':
                  if (passwordCtrl.text.isEmpty) return;
                  credData = {
                    'GameToken': {
                      'provider': 'steam_guard',
                      'secret_key': passwordCtrl.text,
                      'issuer': 'Steam',
                      'account_name': usernameCtrl.text,
                      'url': null,
                    }
                  };
                  break;
                case 'SecureNote':
                  if (notesCtrl.text.isEmpty) return;
                  credData = {'SecureNote': {'note': notesCtrl.text}};
                  break;
              }

              Navigator.pop(ctx);
              await appState.createCredential(
                name: nameCtrl.text,
                credentialType: credType,
                securityLevel: secLevel,
                credentialData: credData,
              );
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  final VoidCallback onCreate;
  const _EmptyState({required this.onCreate});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.badge_outlined, size: 80, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 16),
            Text(
              'No Identities Yet',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              'Create your first identity to start organizing credentials.',
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: onCreate,
              icon: const Icon(Icons.add),
              label: const Text('Create Identity'),
            ),
          ],
        ),
      ),
    );
  }
}