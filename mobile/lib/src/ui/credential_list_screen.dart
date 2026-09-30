/// Credential list screen for a specific identity.
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../ffi/persona_bindings.dart';
import '../state/app_state.dart';
import 'credential_detail_screen.dart';
import 'totp_dialog.dart';

class CredentialListScreen extends StatefulWidget {
  final String identityId;
  final String identityName;
  final String searchQuery;

  const CredentialListScreen({
    super.key,
    required this.identityId,
    required this.identityName,
    required this.searchQuery,
  });

  @override
  State<CredentialListScreen> createState() => _CredentialListScreenState();
}

class _CredentialListScreenState extends State<CredentialListScreen> {
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() => _loading = true);
    await context.read<AppState>().refreshCredentials(widget.identityId);
    if (mounted) setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) {
        final credentials = appState.getCredentials(widget.identityId);
        final filtered = widget.searchQuery.isEmpty
            ? credentials
            : credentials.where((c) {
                final name = (c['name'] as String?)?.toLowerCase() ?? '';
                final username = (c['username'] as String?)?.toLowerCase() ?? '';
                final query = widget.searchQuery.toLowerCase();
                return name.contains(query) || username.contains(query);
              }).toList();

        return RefreshIndicator(
          onRefresh: _refresh,
          child: filtered.isEmpty
              ? ListView(
                  physics: const AlwaysScrollableScrollPhysics(),
                  children: [
                    SizedBox(
                      height: MediaQuery.of(context).size.height * 0.6,
                      child: Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.vpn_key_outlined,
                              size: 64,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(height: 16),
                            Text(
                              widget.searchQuery.isEmpty
                                  ? 'No credentials yet'
                                  : 'No matches for "${widget.searchQuery}"',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Tap + to add your first credential',
                              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                )
              : ListView.separated(
                  padding: const EdgeInsets.all(16),
                  itemCount: filtered.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final cred = filtered[index];
                    return _CredentialTile(
                      credential: cred,
                      onTap: () => _openDetail(cred),
                      onTotp: cred['credential_type'] == 'TwoFactor' ||
                              cred['credential_type'] == 'GameToken'
                          ? () => _showTotp(cred)
                          : null,
                      onDelete: () => _confirmDelete(cred),
                    );
                  },
                ),
        );
      },
    );
  }

  void _openDetail(Map<String, dynamic> cred) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => CredentialDetailScreen(credential: cred),
      ),
    );
  }

  void _showTotp(Map<String, dynamic> cred) async {
    final appState = context.read<AppState>();
    try {
      final result = await appState.generateTotp(cred['id'] as String);
      if (mounted) {
        showDialog(
          context: context,
          builder: (_) => TotpDialog(
            code: result['code'] as String,
            remainingSeconds: result['remaining_seconds'] as int,
            issuer: result['issuer'] as String,
            accountName: result['account_name'] as String,
          ),
        );
      }
    } on PersonaException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to generate TOTP: ${e.message}')),
        );
      }
    }
  }

  Future<void> _confirmDelete(Map<String, dynamic> cred) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Credential?'),
        content: Text('Delete "${cred['name']}"? This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(backgroundColor: Theme.of(ctx).colorScheme.error),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await context.read<AppState>().deleteCredential(cred['id'] as String);
    }
  }
}

class _CredentialTile extends StatelessWidget {
  final Map<String, dynamic> credential;
  final VoidCallback onTap;
  final VoidCallback? onTotp;
  final VoidCallback onDelete;

  const _CredentialTile({
    required this.credential,
    required this.onTap,
    this.onTotp,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final type = credential['credential_type'] as String?;
    final secLevel = credential['security_level'] as String?;

    return Dismissible(
      key: ValueKey(credential['id']),
      direction: DismissDirection.endToStart,
      background: Container(
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.only(right: 20),
        color: theme.colorScheme.errorContainer,
        child: Icon(Icons.delete, color: theme.colorScheme.onErrorContainer),
      ),
      confirmDismiss: (_) async => await showDialog<bool>(
            context: context,
            builder: (ctx) => AlertDialog(
              title: const Text('Delete?'),
              content: Text('Delete "${credential['name']}"?'),
              actions: [
                TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
                FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
              ],
            ),
          ) ??
          false,
      onDismissed: (_) => onDelete(),
      child: Card(
        child: ListTile(
          leading: _typeIcon(type, theme),
          title: Text(credential['name'] as String? ?? 'Untitled'),
          subtitle: Text(_subtitle(credential)),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (onTotp != null)
                IconButton(
                  icon: Icon(Icons.sync, color: theme.colorScheme.primary),
                  onPressed: onTotp,
                  tooltip: 'Show TOTP',
                ),
              _SecurityChip(level: secLevel),
              PopupMenuButton(
                itemBuilder: (ctx) => [
                  const PopupMenuItem(value: 'edit', child: Text('Edit')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete')),
                ],
                onSelected: (v) {
                  if (v == 'delete') onDelete();
                },
              ),
            ],
          ),
          onTap: onTap,
        ),
      ),
    );
  }

  Widget _typeIcon(String? type, ThemeData theme) {
    IconData icon;
    switch (type) {
      case 'Password':
        icon = Icons.key_outlined;
        break;
      case 'TwoFactor':
        icon = Icons.security_outlined;
        break;
      case 'GameToken':
        icon = Icons.videogame_asset_outlined;
        break;
      case 'Passkey':
        icon = Icons.fingerprint_outlined;
        break;
      case 'SecureNote':
        icon = Icons.note_outlined;
        break;
      default:
        icon = Icons.help_outline;
    }
    return CircleAvatar(
      backgroundColor: theme.colorScheme.primaryContainer,
      child: Icon(icon, color: theme.colorScheme.onPrimaryContainer),
    );
  }

  String _subtitle(Map<String, dynamic> cred) {
    final parts = <String>[];
    if (cred['username'] != null && (cred['username'] as String).isNotEmpty) {
      parts.add(cred['username'] as String);
    }
    if (cred['url'] != null && (cred['url'] as String).isNotEmpty) {
      parts.add(cred['url'] as String);
    }
    if (parts.isEmpty) return 'No details';
    return parts.join(' • ');
  }
}

class _SecurityChip extends StatelessWidget {
  final String? level;
  const _SecurityChip({this.level});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    Color color;
    String label;
    switch (level) {
      case 'Critical':
        color = theme.colorScheme.error;
        label = 'CRITICAL';
        break;
      case 'High':
        color = theme.colorScheme.tertiary;
        label = 'HIGH';
        break;
      case 'Medium':
        color = theme.colorScheme.secondary;
        label = 'MED';
        break;
      case 'Low':
        color = theme.colorScheme.outline;
        label = 'LOW';
        break;
      default:
        color = theme.colorScheme.outline;
        label = '?';
    }
    return Container(
      margin: const EdgeInsets.only(left: 8),
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w600,
          color: color,
        ),
      ),
    );
  }
}