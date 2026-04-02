# Conformance Test Specification — NOSTR Mail

> **What any implementation MUST pass to be considered conformant with the NOSTR Mail protocol.**

---

## Test Categories

### Category 1: Event Structure (MUST PASS)

| ID | Test | Requirement |
|----|------|-------------|
| E01 | Kind 1400 rumor has correct structure | `kind: 1400`, `pubkey` set, `tags` array, `content` string |
| E02 | Rumor has NO `id` or `sig` fields | Rumors are unsigned |
| E03 | Recipient `p` tags include role marker | `["p", pubkey, relay, "to"/"cc"]` |
| E04 | Subject tag is present | `["subject", "..."]` |
| E05 | Content-type tag omitted for text/plain | Default is text/plain |
| E06 | Content-type tag present for non-default | `["content-type", "text/markdown"]` |
| E07 | Reply tag references parent event | `["reply", eventId, relayHint]` |
| E08 | Thread tag references root event | `["thread", eventId, relayHint]` |
| E09 | Attachment tags include all fields | `["attachment", hash, filename, mime, size]` |
| E10 | Cashu token tag is present when postage required | `["cashu", serializedToken]` |

### Category 2: Encryption (MUST PASS)

| ID | Test | Requirement |
|----|------|-------------|
| C01 | Seal (kind 13) is correctly formed | `kind: 13`, `pubkey: sender`, empty `tags`, encrypted `content` |
| C02 | Seal content decrypts with NIP-44 | ECDH(recipient, sender) → valid decrypted rumor JSON |
| C03 | Seal signature is valid | Schnorr signature verifies against seal.pubkey |
| C04 | Gift wrap (kind 1059) is correctly formed | `kind: 1059`, `pubkey: ephemeral`, `tags: [["p", recipient]]` |
| C05 | Gift wrap uses ephemeral key (not sender) | wrap.pubkey ≠ sender's pubkey |
| C06 | Gift wrap content decrypts with NIP-44 | ECDH(recipient, ephemeral) → valid seal JSON |
| C07 | Gift wrap signature is valid | Schnorr signature verifies against ephemeral pubkey |
| C08 | Round-trip: wrap(rumor) → unwrap → rumor matches | Content, tags, kind preserved through encrypt/decrypt cycle |
| C09 | Seal timestamp is randomized | seal.created_at ≠ rumor.created_at (within ±2 days) |
| C10 | Wrap timestamp is randomized | wrap.created_at ≠ seal.created_at (within ±2 days) |
| C11 | Different ephemeral keys per recipient | Wrapping same rumor for 2 recipients → different wrap pubkeys |
| C12 | Different ciphertext per wrap (random nonce) | Wrapping same rumor twice → different content |

### Category 3: Anti-Spam (MUST PASS)

| ID | Test | Requirement |
|----|------|-------------|
| S01 | Contact sender → Tier 0 (inbox) | Sender in kind 3 follow list → free delivery |
| S02 | NIP-05 verified → Tier 1 (inbox) | Sender has valid NIP-05 → free delivery |
| S03 | Sufficient PoW → Tier 2 (inbox) | Event PoW ≥ policy threshold → free delivery |
| S04 | Valid Cashu P2PK token → Tier 3 (inbox) | Token amount ≥ threshold, locked to recipient |
| S05 | No qualifying signal → Tier 5 (quarantine) | Unknown sender, no payment → quarantine |
| S06 | Tier evaluation is highest-free-tier-wins | Contact + PoW → Tier 0 (not Tier 2) |
| S07 | Cashu tokens MUST be P2PK locked | Bearer tokens (no P2PK) → rejected |

### Category 4: Mailbox State (MUST PASS)

| ID | Test | Requirement |
|----|------|-------------|
| M01 | Read state is a G-Set (append-only) | markRead → eventId added to reads set |
| M02 | markRead is idempotent | markRead(same ID) twice → same state |
| M03 | Read state cannot be reverted | No operation removes from reads set |
| M04 | State serializes to kind 10099 tags | `["read", eventId]`, `["flagged", eventId]`, `["folder", name, eventId]` |
| M05 | State deserializes from tags | Parse tags → MailboxState matches |
| M06 | State merge: G-Set union for reads | mergeStates: reads = union of both read sets |
| M07 | State merge: both flags preserved | mergeStates: flags from both states included |

### Category 5: Threading (MUST PASS)

| ID | Test | Requirement |
|----|------|-------------|
| T01 | Root message has no parent | No reply/thread tags → root node |
| T02 | Reply links to parent | reply tag → child of that parent |
| T03 | Thread tag always points to root | thread tag → same for all messages in conversation |
| T04 | Thread tree is correctly built | buildThread produces valid parent-child relationships |
| T05 | Chronological ordering within siblings | Children sorted by created_at |
| T06 | Orphaned replies handled | Reply to unknown parent → treated as root |

### Category 6: Interoperability

| ID | Test | Requirement |
|----|------|-------------|
| I01 | Implementation A wraps, Implementation B unwraps | Round-trip across implementations |
| I02 | Same test vectors produce same outputs | Both implementations match test vector expected results |
| I03 | Both handle malformed events gracefully | Invalid kind 1059 → reject, don't crash |
| I04 | Both handle unknown tags gracefully | Unknown tags → ignored, not error |

---

## Running the Tests

Any implementation can validate conformance by:

1. Loading the test vectors from `test-vectors/*.json`
2. Running each vector through their implementation
3. Comparing output against expected results
4. All MUST PASS tests must pass for conformance
5. Report results in TAP (Test Anything Protocol) or JSON format

## Conformance Levels

| Level | Requirements | Meaning |
|-------|-------------|---------|
| **Core** | Categories 1-2 (E01-C12) | Can send and receive encrypted NOSTR Mail |
| **Full** | Categories 1-5 (all) | Full protocol support including anti-spam, state, threading |
| **Interop** | Categories 1-6 | Verified interoperability with another implementation |
