# @nostr-mail/core

TypeScript reference implementation of the NOSTR Mail protocol — encrypted, self-sovereign email on NOSTR.

## Install

```bash
npm install @nostr-mail/core
```

## Quick Start

```typescript
import { NostrMail } from '@nostr-mail/core'

// Initialize with NIP-07 signer or private key
const mail = NostrMail.init({ privateKey: 'your-hex-nsec' })

// Send encrypted mail
await mail.send({
  to: 'bob@example.com',
  subject: 'Hello from NOSTR Mail',
  body: 'The future of email is here.',
})

// Receive mail (async iterator)
for await (const msg of mail.inbox()) {
  console.log(`From: ${msg.from.name}`)
  console.log(`Subject: ${msg.subject}`)
  console.log(`Body: ${msg.body}`)
}
```

## Features

- NIP-44 authenticated encryption (ChaCha20 + HMAC-SHA256)
- NIP-59 Gift Wrap (three-layer metadata hiding)
- Cashu P2PK ecash postage for anti-spam (NUT-11)
- Blossom encrypted file attachments
- Thread reconstruction
- Mailbox state sync (G-Set reads, multi-device)
- NIP-05 address resolution
- 3-tier anti-spam evaluation (contacts, Cashu postage, quarantine)

## Modules

| Module | Purpose |
|--------|---------|
| `mail.ts` | Kind 1400 event creation and parsing |
| `wrap.ts` | NIP-59 seal + gift wrap (send path) |
| `unwrap.ts` | NIP-59 unwrap + unseal (receive path) |
| `address.ts` | NIP-05 resolution + relay discovery |
| `cashu.ts` | Cashu P2PK token creation + verification |
| `attachment.ts` | Blossom encrypted file references |
| `relay.ts` | Relay pool, publish, subscribe |
| `spam.ts` | Anti-spam tier evaluation |
| `state.ts` | Mailbox state management |
| `thread.ts` | Thread tree reconstruction |

## Test Vectors

Canonical test vectors in `test-vectors/` — any implementation must produce identical results.

## License

MIT


---

## Project Layout — NOSTR Mail Ecosystem

The NOSTR Mail project is split across six repositories with clear ownership of each artifact:

| Repo | Source of truth for | This repo? |
|---|---|---|
| [nostr-mail-spec](https://github.com/luthen-seas/nostr-mail-spec) | Living spec, threat model, decisions log, design docs |  |
| [nostr-mail-nip](https://github.com/luthen-seas/nostr-mail-nip) | Submission-ready NIP draft, **canonical test vectors** |  |
| [nostr-mail-ts](https://github.com/luthen-seas/nostr-mail-ts) | TypeScript reference implementation | ✅ |
| [nostr-mail-go](https://github.com/luthen-seas/nostr-mail-go) | Go second implementation (interop) |  |
| [nostr-mail-bridge](https://github.com/luthen-seas/nostr-mail-bridge) | SMTP ↔ NOSTR gateway |  |
| [nostr-mail-client](https://github.com/luthen-seas/nostr-mail-client) | Reference web client (SvelteKit) |  |

**Test vectors** are canonical in `nostr-mail-nip/test-vectors/` and consumed by the implementation repos via git submodule. Do not edit a local copy in an impl repo — submit changes to `nostr-mail-nip`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the cross-repo contribution workflow, [SECURITY.md](SECURITY.md) for vulnerability reporting, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.
