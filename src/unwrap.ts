// ─── NOSTR Mail Protocol — Decryption (Receive Path) ────────────────────────
// Unwraps a kind 1059 gift wrap → kind 13 seal → kind 15 rumor.

import { verifyEvent } from 'nostr-tools'
import * as nip44 from 'nostr-tools/nip44'
import type { MailMessage } from './types.js'

/**
 * Compute NIP-44 conversation key from a private key and a public key.
 */
function getConversationKey(privkey: Uint8Array, pubkey: string): Uint8Array {
  return nip44.v2.utils.getConversationKey(privkey, pubkey)
}

/** The verified result of unwrapping a gift-wrapped mail event. */
export interface UnwrapResult {
  /** The decrypted kind 15 mail rumor. */
  rumor: MailMessage
  /** The sender's hex public key (from the seal layer). */
  senderPubkey: string
  /** Whether the seal signature was cryptographically verified. */
  verified: boolean
}

/**
 * Unwrap and decrypt a kind 1059 gift wrap event to reveal the mail inside.
 *
 * Performs the full two-layer decryption:
 * 1. Decrypt the gift wrap (kind 1059) with ECDH(recipientPrivkey, wrap.pubkey)
 *    to reveal the seal (kind 13).
 * 2. Verify the seal's signature to authenticate the sender.
 * 3. Decrypt the seal with ECDH(recipientPrivkey, seal.pubkey) to reveal
 *    the rumor (kind 15).
 *
 * @param wrapEvent - A kind 1059 gift wrap event received from a relay.
 * @param recipientPrivkey - The recipient's private key (32 bytes).
 * @returns The decrypted rumor, sender pubkey, and verification status.
 * @throws If decryption fails or the event structure is invalid.
 */
export async function unwrapMail(
  wrapEvent: {
    id: string
    pubkey: string
    content: string
    kind: number
    created_at: number
    tags: string[][]
    sig: string
  },
  recipientPrivkey: Uint8Array,
): Promise<UnwrapResult> {
  // ── Validate wrap event ───────────────────────────────────────────────
  if (wrapEvent.kind !== 1059) {
    throw new Error(`Expected kind 1059 gift wrap, got kind ${wrapEvent.kind}`)
  }

  // ── Layer 1: Decrypt the gift wrap → seal ─────────────────────────────
  const wrapConvKey = getConversationKey(recipientPrivkey, wrapEvent.pubkey)

  let sealJson: string
  try {
    sealJson = nip44.v2.decrypt(wrapEvent.content, wrapConvKey)
  } catch (err) {
    throw new Error(
      `Failed to decrypt gift wrap: ${err instanceof Error ? err.message : 'unknown error'}`,
    )
  }

  let seal: {
    id: string
    pubkey: string
    content: string
    kind: number
    created_at: number
    tags: string[][]
    sig: string
  }

  try {
    seal = JSON.parse(sealJson)
  } catch {
    throw new Error('Decrypted gift wrap content is not valid JSON')
  }

  // Validate seal structure
  if (seal.kind !== 13) {
    throw new Error(`Expected kind 13 seal, got kind ${seal.kind}`)
  }

  // ── Verify seal signature (sender authentication) ─────────────────────
  const verified = verifyEvent(seal)

  // ── Layer 2: Decrypt the seal → rumor ─────────────────────────────────
  const sealConvKey = getConversationKey(recipientPrivkey, seal.pubkey)

  let rumorJson: string
  try {
    rumorJson = nip44.v2.decrypt(seal.content, sealConvKey)
  } catch (err) {
    throw new Error(
      `Failed to decrypt seal: ${err instanceof Error ? err.message : 'unknown error'}`,
    )
  }

  let rumor: MailMessage
  try {
    rumor = JSON.parse(rumorJson)
  } catch {
    throw new Error('Decrypted seal content is not valid JSON')
  }

  // Validate rumor structure
  if (rumor.kind !== 15) {
    throw new Error(`Expected kind 15 mail rumor, got kind ${rumor.kind}`)
  }

  return {
    rumor,
    senderPubkey: seal.pubkey,
    verified,
  }
}

/**
 * Try to unwrap a mail event, returning null instead of throwing on failure.
 *
 * Useful for batch processing where some events may not be decryptable
 * (e.g., the recipient key doesn't match, or the event is corrupted).
 *
 * @param wrapEvent - A kind 1059 gift wrap event.
 * @param recipientPrivkey - The recipient's private key (32 bytes).
 * @returns The unwrap result, or null if decryption/verification failed.
 */
export async function tryUnwrapMail(
  wrapEvent: {
    id: string
    pubkey: string
    content: string
    kind: number
    created_at: number
    tags: string[][]
    sig: string
  },
  recipientPrivkey: Uint8Array,
): Promise<UnwrapResult | null> {
  try {
    return await unwrapMail(wrapEvent, recipientPrivkey)
  } catch {
    return null
  }
}
