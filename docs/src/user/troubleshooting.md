# Troubleshooting

## Unlocking and Passwords

**Wrong master password, vault will not open**
There is no recovery path (no escrow, no reset). If you made an encrypted export
(`persona export --encrypt`), importing that backup gets your data back to the
moment of the export; changes made after that point are unrecoverable.

**Biometric unlock unavailable**
Biometrics are only a convenience layer for unlocking — the master password
always works. Desktop biometrics depend on the OS keychain (service name
`persona-biometric`) — if the system keychain gets wiped, unlock with the master
password and re-enroll.

## Vault and Data

**Suspect the vault file is corrupted (SQLite / migration errors)**
Restore from the most recent backup (`persona import <backup-file> --decrypt`
or a full-vault restore). Local changes made after the snapshot point will be
lost — which is exactly why backups should be regular. On Windows, first make
sure no other Persona process holds the vault file.

**Accidentally deleted an identity / credential**
Deletion is local and immediate. The recovery path is the same as above:
restore an older backup. If you make frequent day-to-day changes, raise your
backup cadence accordingly.

## Sync (Multi-Device)

**Sync is stuck — walk the chain**

1. Is the server alive: `curl http://<server>/health` should return 200;
2. Is this device in the group: check the device list and authorization status
   in desktop "Settings → Sync Devices" (**an envelope icon = authorized**;
   unauthorized devices receive no data);
3. Trigger manually: run a round with the "Sync Now" button and read the error
   message.

**Rotating the group key reports "another device just finished rotating" (409 / CONCURRENT_CONFLICT)**
Normal behavior: concurrent rotations are rejected by the epoch optimistic lock,
and **your data is unaffected**. Click rotate again shortly after (the client
will rerun with the new epoch).

**A device is lost / stolen**
**Revoke** it from another authorized device (envelope and session state are
cleared in cascade, effective immediately), then **rotate the group key** — the
revoked device cannot obtain the new envelope, and subsequent data stays
invisible to it.

**A new device receives no data**
Confirm it is authorized (envelope icon present); then check whether the
server's oplog retention window is at least as long as the time since that
device was last online — history that fell out of the window is not re-delivered,
but the device's local vault is not lost.

## Browser Extension and SSH Agent

**The extension cannot connect to the desktop app**
The desktop app must be running (Native Messaging bridge); check that the
extension-desktop pairing exists (re-pairing rebuilds it). For protocol details,
see
[BRIDGE_PROTOCOL.md](https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md).

**The SSH Agent refuses to sign**
First check whether a policy is blocking it: known_hosts verification,
per-key/per-host confirmation, and rate limits all actively refuse — that is
designed behavior, not a malfunction. The audit log contains the corresponding
refusal record.

## Platforms

**macOS / Windows**
Not verified on real hardware and support is not claimed; the CLI presumably
compiles but has no test backing. The desktop deb is Linux-only.

For more background:
[STORAGE_AND_SYNC.md failure-consequences quick reference](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md),
[THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).
