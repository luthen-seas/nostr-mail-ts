// ─── NOSTR Mail Protocol — NIP-59 Seal + Gift Wrap ──────────────────────────
// Three-layer encryption: rumor → seal (kind 13) → gift wrap (kind 1059).
// Uses NIP-44 (versioned encryption) for both encryption layers.

import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools'
import * as nip44 from 'nostr-tools/nip44'
import type { MailMessage } from './types.js'

/**
 * Generate a random timestamp offset within ±2 days.
 *
 * This prevents timing correlation between the seal and wrap layers.
 * Uses crypto.getRandomValues() for cryptographic randomness.
 */
function randomTimestampOffset(): number {
  const maxOffset = 172800 // 2 days in seconds
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  // Map [0, 2^32) to [-maxOffset, +maxOffset]
  const normalized = (buf[0]! / 0x100000000) * 2 - 1
  return Math.floor(normalized * maxOffset)
}

/**
 * Compute NIP-44 conversation key from a private key and a public key.
 */
function getConversationKey(privkey: Uint8Array, pubkey: string): Uint8Array {
  return nip44.v2.utils.getConversationKey(privkey, pubkey)
}

/**
 * Seal and gift-wrap a mail rumor for a specific recipient.
 *
 * Implements the three-layer NIP-59 encryption:
 * 1. **Rumor** (kind 15, unsigned) — the actual mail content
 * 2. **Seal** (kind 13, signed by sender) — NIP-44 encrypts the rumor
 *    using ECDH(sender, recipient). Timestamp randomized ±2 days.
 * 3. **Gift Wrap** (kind 1059, signed by ephemeral key) — NIP-44 encrypts
 *    the seal using ECDH(ephemeral, recipient). Timestamp randomized ±2 days.
 *
 * The wrap event includes a `["p", recipientPubkey]` tag so relays can
 * route it to the recipient's inbox.
 *
 * @param rumor - The kind 15 mail rumor (unsigned).
 * @param senderPrivkey - Sender's private key (32 bytes).
 * @param recipientPubkey - Recipient's hex public key.
 * @returns A signed kind 1059 gift wrap event ready for relay publication.
 */
export async function wrapMail(
  rumor: MailMessage,
  senderPrivkey: Uint8Array,
  recipientPubkey: string,
): Promise<ReturnType<typeof finalizeEvent>> {
  const now = Math.floor(Date.now() / 1000)

  // ── Layer 1: Serialize the rumor ──────────────────────────────────────
  const rumorJson = JSON.stringify(rumor)

  // ── Layer 2: Seal (kind 13) ───────────────────────────────────────────
  // Encrypt rumor with NIP-44 using ECDH(sender, recipient)
  const sealConvKey = getConversationKey(senderPrivkey, recipientPubkey)
  const encryptedRumor = nip44.v2.encrypt(rumorJson, sealConvKey)

  const sealTemplate = {
    kind: 13,
    created_at: now + randomTimestampOffset(),
    tags: [],
    content: encryptedRumor,
  }

  // Sign the seal with the sender's key (this proves sender identity)
  const seal = finalizeEvent(sealTemplate, senderPrivkey)

  // ── Layer 3: Gift Wrap (kind 1059) ────────────────────────────────────
  // Generate ephemeral keypair (used once, then discarded)
  const ephemeralPrivkey = generateSecretKey()

  // Encrypt the seal with NIP-44 using ECDH(ephemeral, recipient)
  const wrapConvKey = getConversationKey(ephemeralPrivkey, recipientPubkey)
  const sealJson = JSON.stringify(seal)
  const encryptedSeal = nip44.v2.encrypt(sealJson, wrapConvKey)

  const wrapTemplate = {
    kind: 1059,
    created_at: now + randomTimestampOffset(),
    tags: [['p', recipientPubkey]],
    content: encryptedSeal,
  }

  // Sign the wrap with the ephemeral key
  const wrap = finalizeEvent(wrapTemplate, ephemeralPrivkey)

  return wrap
}

/** A wrapped event paired with relay targets for publication. */
export interface WrappedMailResult {
  /** The signed kind 1059 gift wrap event. */
  wrap: ReturnType<typeof finalizeEvent>
  /** Relay URLs where this wrap should be published. */
  relays: string[]
}

/**
 * Wrap a rumor for multiple recipients, plus a self-copy.
 *
 * Each recipient gets their own independent gift wrap (different ephemeral
 * keys, different encryption). BCC recipients are included in the wraps but
 * their `p` tags are only in their own individual wraps — not visible to
 * other recipients (the rumor's `p` tags include BCC, but each wrap only
 * routes to one recipient via its outer `p` tag).
 *
 * A self-copy is always created so the sender can read their own sent mail.
 *
 * @param rumor - The kind 15 mail rumor (unsigned).
 * @param senderPrivkey - Sender's private key (32 bytes).
 * @param recipients - Array of recipient pubkeys with relay preferences.
 * @returns Array of wrapped events, one per recipient plus one self-copy.
 */
export async function wrapMailForRecipients(
  rumor: MailMessage,
  senderPrivkey: Uint8Array,
  recipients: Array<{ pubkey: string; relays: string[] }>,
): Promise<WrappedMailResult[]> {
  const senderPubkey = getPublicKey(senderPrivkey)
  const results: WrappedMailResult[] = []

  // Wrap for each recipient
  for (const recipient of recipients) {
    const wrap = await wrapMail(rumor, senderPrivkey, recipient.pubkey)
    results.push({ wrap, relays: recipient.relays })
  }

  // Self-copy: wrap for the sender so they can read sent mail
  // Only add if the sender isn't already in the recipients list
  const senderInRecipients = recipients.some(r => r.pubkey === senderPubkey)
  if (!senderInRecipients) {
    const selfWrap = await wrapMail(rumor, senderPrivkey, senderPubkey)
    results.push({ wrap: selfWrap, relays: [] }) // sender's own relays
  }

  return results
}

/**
 * Unwrap the outer gift wrap layer only (kind 1059 → kind 13 seal).
 *
 * This is a lower-level utility. Most callers should use `unwrapMail`
 * from the `unwrap` module which handles both layers.
 *
 * @param wrapEvent - The kind 1059 gift wrap event.
 * @param recipientPrivkey - Recipient's private key (32 bytes).
 * @returns The decrypted and parsed seal event.
 */
export function unwrapGiftWrap(
  wrapEvent: { pubkey: string; content: string },
  recipientPrivkey: Uint8Array,
): unknown {
  const convKey = getConversationKey(recipientPrivkey, wrapEvent.pubkey)
  const decrypted = nip44.v2.decrypt(wrapEvent.content, convKey)
  return JSON.parse(decrypted) as unknown
}

/**
 * Decrypt the seal layer (kind 13 → kind 15 rumor).
 *
 * @param seal - The kind 13 seal event.
 * @param recipientPrivkey - Recipient's private key (32 bytes).
 * @returns The decrypted rumor and the verified sender pubkey.
 */
export function unwrapSeal(
  seal: { pubkey: string; content: string; id: string; sig: string; kind: number; created_at: number; tags: string[][] },
  recipientPrivkey: Uint8Array,
): { rumor: MailMessage; senderPubkey: string; verified: boolean } {
  // Verify seal signature to confirm sender identity
  const verified = verifyEvent(seal)

  // Decrypt the rumor using ECDH(recipient, seal.pubkey i.e. sender)
  const convKey = getConversationKey(recipientPrivkey, seal.pubkey)
  const decrypted = nip44.v2.decrypt(seal.content, convKey)
  const rumor = JSON.parse(decrypted) as MailMessage

  return {
    rumor,
    senderPubkey: seal.pubkey,
    verified,
  }
}
