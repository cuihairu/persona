/// Search delegate for credentials across all identities.
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class _PersonaSearchDelegate extends SearchDelegate<List<dynamic>> {
  @override
  List<Widget> buildActions(BuildContext context) => [
        IconButton(icon: const Icon(Icons.clear), onPressed: () => query = ''),
      ];

  @override
  Widget buildLeading(BuildContext context) => IconButton(
        icon: const Icon(Icons.arrow_back),
        onPressed: () => close(context, []),
      );

  @override
  Widget buildResults(BuildContext context) => _buildResults(context);

  @override
  Widget buildSuggestions(BuildContext context) => _buildResults(context);

  Widget _buildResults(BuildContext context) {
    return FutureBuilder<List<dynamic>>(
      future: context.read<AppState>().searchCredentials(query),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snapshot.hasError) {
          return Center(child: Text('Search error: ${snapshot.error}'));
        }
        final results = snapshot.data ?? [];
        if (results.isEmpty) {
          return Center(
            child: Text(query.isEmpty ? 'Start typing to search' : 'No results for "$query"'),
          );
        }
        return ListView.separated(
          padding: const EdgeInsets.all(16),
          itemCount: results.length,
          separatorBuilder: (_, __) => const SizedBox(height: 8),
          itemBuilder: (context, index) {
            final cred = results[index];
            return _SearchResultTile(credential: cred);
          },
        );
      },
    );
  }
}

class _SearchResultTile extends StatelessWidget {
  final Map<String, dynamic> credential;
  const _SearchResultTile({required this.credential});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final type = credential['credential_type'] as String?;
    return Card(
      child: ListTile(
        leading: _typeIcon(type),
        title: Text(credential['name'] as String? ?? 'Untitled'),
        subtitle: Text(_subtitle(credential)),
        trailing: _SecurityChip(level: credential['security_level'] as String?),
        onTap: () {
          close(context, []);
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => CredentialDetailScreen(credential: credential),
            ),
          );
        },
      ),
    );
  }

  Widget _typeIcon(String? type) {
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
    if (cred['identity_name'] != null && (cred['identity_name'] as String).isNotEmpty) {
      parts.add(cred['identity_name'] as String);
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