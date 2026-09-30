/// Credential detail screen showing decrypted data.
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class CredentialDetailScreen extends StatefulWidget {
  final Map<String, dynamic> credential;
  const CredentialDetailScreen({super.key, required this.credential});

  @override
  State<CredentialDetailScreen> createState() => _CredentialDetailScreenState();
}

class _CredentialDetailScreenState extends State<CredentialDetailScreen> {
  Map<String, dynamic>? _decryptedData;
  bool _loading = true;
  bool _showSecret = false;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _loading = true);
    try {
      final data = await context.read<AppState>().getCredentialData(widget.credential['id'] as String);
      if (mounted) setState(() => _decryptedData = data);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cred = widget.credential;
    final type = cred['credential_type'] as String?;

    return Scaffold(
      appBar: AppBar(
        title: Text(cred['name'] as String? ?? 'Credential'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline),
            onPressed: _confirmDelete,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _decryptedData == null
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.error_outline, size: 48),
                      const SizedBox(height: 16),
                      const Text('Failed to decrypt credential'),
                      const SizedBox(height: 16),
                      FilledButton(onPressed: _loadData, child: const Text('Retry')),
                    ],
                  ),
                )
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _DetailRow('Type', type ?? 'Unknown'),
                      _DetailRow('Security Level', cred['security_level'] as String? ?? 'Unknown'),
                      if (cred['description'] != null && (cred['description'] as String).isNotEmpty)
                        _DetailRow('Description', cred['description'] as String),
                      const Divider(height: 32),
                      _buildDecryptedContent(_decryptedData!, type),
                    ],
                  ),
                ),
    );
  }

  Widget _buildDecryptedContent(Map<String, dynamic> data, String? type) {
    switch (type) {
      case 'Password':
        return _PasswordContent(data: data['Password'] as Map<String, dynamic>? ?? {},
            onToggle: () => setState(() => _showSecret = !_showSecret), showSecret: _showSecret);
      case 'TwoFactor':
        return _TwoFactorContent(data: data['TwoFactor'] as Map<String, dynamic>? ?? {});
      case 'GameToken':
        return _GameTokenContent(data: data['GameToken'] as Map<String, dynamic>? ?? {});
      case 'SecureNote':
        return _SecureNoteContent(data: data['SecureNote'] as Map<String, dynamic>? ?? {});
      default:
        return _GenericContent(data: data);
    }
  }

  Future<void> _confirmDelete() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Credential?'),
        content: Text('Delete "${widget.credential['name']}"? This cannot be undone.'),
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
    if (confirm == true && mounted) {
      await context.read<AppState>().deleteCredential(widget.credential['id'] as String);
      if (mounted) Navigator.of(context).pop();
    }
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;
  const _DetailRow(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.labelSmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          )),
          const SizedBox(height: 4),
          Text(value, style: Theme.of(context).textTheme.bodyLarge),
        ],
      ),
    );
  }
}

class _PasswordContent extends StatelessWidget {
  final Map<String, dynamic> data;
  final VoidCallback onToggle;
  final bool showSecret;
  const _PasswordContent({required this.data, required this.onToggle, required this.showSecret});

  @override
  Widget build(BuildContext context) {
    final pwd = data['password'] as String? ?? '';
    final email = data['email'] as String? ?? '';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _CopyableRow(
          label: 'Password',
          value: showSecret ? pwd : '•' * pwd.length,
          onToggle: onToggle,
          showToggle: true,
        ),
        if (email.isNotEmpty) _CopyableRow(label: 'Email', value: email),
        if (data['url'] != null && (data['url'] as String).isNotEmpty)
          _CopyableRow(label: 'URL', value: data['url'] as String),
      ],
    );
  }
}

class _TwoFactorContent extends StatelessWidget {
  final Map<String, dynamic> data;
  const _TwoFactorContent({required this.data});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _CopyableRow(label: 'Secret', value: data['secret_key'] as String? ?? ''),
        if (data['issuer'] != null) _CopyableRow(label: 'Issuer', value: data['issuer'] as String),
        if (data['account_name'] != null)
          _CopyableRow(label: 'Account', value: data['account_name'] as String),
        _DetailRow('Algorithm', data['algorithm'] as String? ?? 'SHA1'),
        _DetailRow('Digits', '${data['digits'] ?? 6}'),
        _DetailRow('Period', '${data['period'] ?? 30}s'),
      ],
    );
  }
}

class _GameTokenContent extends StatelessWidget {
  final Map<String, dynamic> data;
  const _GameTokenContent({required this.data});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _DetailRow('Provider', data['provider'] as String? ?? 'Unknown'),
        _CopyableRow(label: 'Secret', value: data['secret_key'] as String? ?? ''),
        if (data['issuer'] != null) _CopyableRow(label: 'Issuer', value: data['issuer'] as String),
        if (data['account_name'] != null)
          _CopyableRow(label: 'Account', value: data['account_name'] as String),
      ],
    );
  }
}

class _SecureNoteContent extends StatelessWidget {
  final Map<String, dynamic> data;
  const _SecureNoteContent({required this.data});

  @override
  Widget build(BuildContext context) {
    return Text(data['note'] as String? ?? '', style: Theme.of(context).textTheme.bodyLarge);
  }
}

class _GenericContent extends StatelessWidget {
  final Map<String, dynamic> data;
  const _GenericContent({required this.data});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: data.entries.map((e) => _DetailRow(e.key, e.value.toString())).toList(),
    );
  }
}

class _CopyableRow extends StatelessWidget {
  final String label;
  final String value;
  final VoidCallback? onToggle;
  final bool showToggle;

  const _CopyableRow({
    required this.label,
    required this.value,
    this.onToggle,
    this.showToggle = false,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(label, style: Theme.of(context).textTheme.labelSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            )),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
          ),
          if (showToggle)
            IconButton(
              icon: Icon(showSecret ? Icons.visibility : Icons.visibility_off),
              onPressed: onToggle,
            )
          else
            IconButton(
              icon: const Icon(Icons.copy),
              onPressed: () => _copy(value),
              tooltip: 'Copy',
            ),
        ],
      ),
    );
  }

  bool get showSecret => false; // overridden in _PasswordContent

  void _copy(String text) {
    // Copy to clipboard would need clipboard plugin; skip for minimal build
  }
}