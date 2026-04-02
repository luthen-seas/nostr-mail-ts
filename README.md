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
- 6-tier anti-spam evaluation

## Modules

| Module | Purpose |
|--------|---------|
| `mail.ts` | Kind 1111 event creation and parsing |
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
