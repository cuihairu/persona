/// TOTP code display dialog with countdown.
import 'package:flutter/material.dart';
import 'dart:async';

class TotpDialog extends StatefulWidget {
  final String code;
  final int remainingSeconds;
  final String issuer;
  final String accountName;

  const TotpDialog({
    super.key,
    required this.code,
    required this.remainingSeconds,
    required this.issuer,
    required this.accountName,
  });

  @override
  State<TotpDialog> createState() => _TotpDialogState();
}

class _TotpDialogState extends State<TotpDialog> {
  late int _remaining;
  late String _code;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _remaining = widget.remainingSeconds;
    _code = widget.code;
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_remaining > 0) {
        setState(() => _remaining--);
      } else {
        _timer?.cancel();
        if (mounted) Navigator.of(context).pop();
      }
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final progress = _remaining / widget.remainingSeconds;

    return AlertDialog(
      title: Row(
        children: [
          Icon(Icons.security, color: theme.colorScheme.primary),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(widget.issuer, style: theme.textTheme.titleMedium),
                Text(widget.accountName, style: theme.textTheme.bodySmall),
              ],
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Code display
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  _formatCode(_code),
                  style: theme.textTheme.displayMedium?.copyWith(
                    fontFamily: 'monospace',
                    fontWeight: FontWeight.w500,
                    letterSpacing: 8,
                  ),
                ),
                const SizedBox(width: 16),
                IconButton(
                  icon: const Icon(Icons.copy),
                  onPressed: () => _copyCode(),
                  tooltip: 'Copy',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Countdown progress
          LinearProgressIndicator(
            value: progress,
            minHeight: 6,
            borderRadius: BorderRadius.circular(3),
            backgroundColor: theme.colorScheme.surfaceContainerHighest,
            valueColor: AlwaysStoppedAnimation(theme.colorScheme.primary),
          ),
          const SizedBox(height: 8),
          Text(
            'Refreshes in ${_remaining}s',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }

  String _formatCode(String code) {
    // Insert space every 3 digits for 6-digit codes
    if (code.length == 6) return '${code.substring(0, 3)} ${code.substring(3)}';
    return code;
  }

  void _copyCode() {
    // Would need clipboard plugin; skip for minimal build
  }
}