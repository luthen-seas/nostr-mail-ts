# NOSTR Mail Test Vectors

Canonical test vectors for the NOSTR Mail protocol (kind 15). Any conforming implementation MUST produce identical results for deterministic operations and pass all round-trip checks for non-deterministic operations (encryption).

## File Index

| File | Contents |
|------|----------|
| `mail-event.json` | Kind 15 mail event (rumor) creation |
| `gift-wrap.json` | NIP-59 seal + gift wrap encryption flow |
| `thread.json` | Thread reconstruction from reply/thread tags |
| `spam-tier.json` | Anti-spam tier evaluation |
| `state.json` | Mailbox state (kind 10099) CRDT operations |

## Test Keys

All vectors use these deterministic keys:

| Identity | Private Key (hex) | Public Key (hex) |
|----------|-------------------|------------------|
| Alice | `7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a` | `2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a6748` |
| Bob | `c15d2a640a7bd00f291e074e5e40419e08593833a5b9bd1b4e89100ef750fa35` | `98b30d5bfd1e2e751d7a57e7a58e67e15b3f2e0a90f9f7e8e40f7f6e5d4c3b2a` |
| Charlie | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2` | `d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4` |

## How to Use

### Deterministic vectors (mail-event, thread, spam-tier, state)

Compare your implementation's output field-by-field against the `expected` object. Fields must match exactly (kind, tags order, tag contents, content string).

### Non-deterministic vectors (gift-wrap)

NIP-44 encryption uses random nonces and gift wraps use ephemeral keys, so ciphertext will differ on every run. Instead, verify:

1. **Structure**: Output event has the correct kind, tag structure, and field presence.
2. **Round-trip**: `decrypt(encrypt(plaintext)) == plaintext` for every vector.
3. **Signatures**: Seal signature is valid for sender's pubkey; wrap signature is valid for the ephemeral pubkey included in the wrap.
4. **Tag correctness**: Gift wrap `p` tag matches the intended recipient.

### JSON conventions

- `"description"` fields explain the vector's purpose.
- `"note"` fields clarify non-obvious behavior or edge cases.
- All timestamps are Unix seconds (UTC).
- All keys and hashes are lowercase hex.
- Event IDs referenced in threading vectors are synthetic 64-char hex strings for readability (prefixed with `aaa...`, `bbb...`, etc.).
