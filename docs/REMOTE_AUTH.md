# Remote Authentication (SRP-like Abstraction)

Persona prepares for a future client-server sync model by exposing a protocol-agnostic abstraction that mirrors the Secure Remote Password (SRP) workflow. The goal is to avoid sending master passwords to the server while still deriving a mutually authenticated session key.

## Components

* `SrpParameters`: server-provided modulus/generator/salt tuple (hex encoded for easier transport).
* `SrpHandshake`: client and server public values (`A`/`B` in SRP terminology).
* `SrpProof`: message authentication (`M1`/`M2`).
* `RemoteAuthProvider`: trait that begins/finalizes the handshake.
* `MockRemoteAuthProvider`: default in-memory placeholder so CLIs can run offline.

## Flow

1. Client calls `begin_remote_auth(username)` which returns:
   * Random `user_id` (UUID placeholder until real server IDs exist).
   * `SrpParameters` (currently mocked with small values).
   * `SrpHandshake` containing the server public value and a placeholder client public.
2. Client derives its proof locally and calls `finalize_remote_auth(challenge, client_proof)`.
3. Provider verifies the client proof and returns `RemoteAuthResult` (server proof + session key fingerprint).
4. Higher layers can now bind this fingerprint to the unlock key/sessions.

The mock provider serves tests/UI wiring only; server implementations will supply real SRP math and persist salts/verifiers.
