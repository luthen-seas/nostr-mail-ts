// ─── NOSTR Mail Protocol — Public API ───────────────────────────────────────
// Re-exports all modules and provides the high-level NostrMail class.

// ── Type exports ────────────────────────────────────────────────────────────
export type {
  MailMessage,
  ParsedMail,
  MailIdentity,
  MailAttachment,
  CashuPostage,
  SpamTier,
  SpamPolicy,
  MailboxState,
  SendOptions,
  AttachmentInput,
  NostrMailConfig,
  Signer,
  ThreadNode,
} from './types.js'

// ── Module exports ──────────────────────────────────────────────────────────
export { createMailRumor, parseMailRumor } from './mail.js'
export type { CreateMailRumorParams, ParsedMailRumor } from './mail.js'

export { wrapMail, wrapMailForRecipients, unwrapGiftWrap, unwrapSeal } from './wrap.js'
export type { WrappedMailResult } from './wrap.js'

export { unwrapMail, tryUnwrapMail } from './unwrap.js'
export type { UnwrapResult } from './unwrap.js'

export { buildThread, flattenThread, groupByThread, threadSummaries } from './thread.js'

export {
  evaluateSpamTier,
  createSpamPolicy,
  parsePolicyTags,
  policyToTags,
  DEFAULT_SPAM_POLICY,
} from './spam.js'

export {
  createMailboxState,
  markRead,
  isRead,
  toggleFlag,
  getFlags,
  moveToFolder,
  getFolder,
  markDeleted,
  mergeStates,
  stateToTags,
  tagsToState,
} from './state.js'

// ── High-level NostrMail class ──────────────────────────────────────────────

import { getPublicKey } from 'nostr-tools'
import type {
  NostrMailConfig,
  SendOptions,
  ParsedMail,
  SpamPolicy,
  MailboxState,
  Signer,
} from './types.js'
import { createMailRumor, parseMailRumor } from './mail.js'
import { wrapMailForRecipients } from './wrap.js'
import { tryUnwrapMail } from './unwrap.js'
import { evaluateSpamTier, createSpamPolicy } from './spam.js'
import { buildThread, flattenThread, groupByThread } from './thread.js'
import {
  createMailboxState,
  markRead as stateMarkRead,
  mergeStates,
} from './state.js'

/**
 * High-level NOSTR Mail client.
 *
 * Wraps the lower-level protocol functions into a convenient interface.
 * Supports both direct private key signing and external signers (NIP-07/46).
 *
 * @example
 * ```typescript
 * import { NostrMail } from '@nostr-mail/core'
 *
 * const mail = new NostrMail({
 *   privateKey: 'hex-encoded-privkey',
 *   relays: ['wss://relay.example.com'],
 * })
 *
 * // Send a message
 * const wraps = await mail.send({
 *   to: 'recipient-hex-pubkey',
 *   subject: 'Hello from NOSTR Mail',
 *   body: 'This is an end-to-end encrypted message.',
 * })
 *
 * // Decrypt a received message
 * const parsed = await mail.receive(giftWrapEvent)
 * ```
 */
export class NostrMail {
  private readonly privkey: Uint8Array | null
  private readonly signer: Signer | null
  private readonly relays: string[]
  private readonly spamPolicy: SpamPolicy
  private state: MailboxState

  constructor(config: NostrMailConfig) {
    if (!config.privateKey && !config.signer) {
      throw new Error('NostrMail requires either a privateKey or a signer')
    }

    this.privkey = config.privateKey ? hexToBytes(config.privateKey) : null
    this.signer = config.signer ?? null
    this.relays = config.relays ?? []
    this.spamPolicy = createSpamPolicy(config.spamPolicy)
    this.state = createMailboxState()
  }

  /**
   * Get this user's hex public key.
   */
  async getPublicKey(): Promise<string> {
    if (this.privkey) {
      return getPublicKey(this.privkey)
    }
    if (this.signer) {
      return this.signer.getPublicKey()
    }
    throw new Error('No signing method available')
  }

  /**
   * Compose and wrap a mail message for all recipients.
   *
   * Creates a kind 1400 rumor, then gift-wraps it individually for each
   * recipient (To, CC, BCC) plus a self-copy. Returns the wrapped events
   * ready for relay publication.
   *
   * @param options - Mail composition options.
   * @returns Array of wrapped events with target relay URLs.
   */
  async send(options: SendOptions): Promise<Array<{ wrap: unknown; relays: string[] }>> {
    if (!this.privkey) {
      throw new Error('Direct send requires a private key. Use a signer for NIP-07/46 workflows.')
    }

    const senderPubkey = getPublicKey(this.privkey)

    // Normalize recipients to arrays
    const toList = normalizeRecipients(options.to)
    const ccList = normalizeRecipients(options.cc)
    const bccList = normalizeRecipients(options.bcc)

    // Build recipient list with roles
    const recipients = [
      ...toList.map(pubkey => ({ pubkey, role: 'to' as const })),
      ...ccList.map(pubkey => ({ pubkey, role: 'cc' as const })),
      ...bccList.map(pubkey => ({ pubkey, role: 'bcc' as const })),
    ]

    // Create the kind 1400 rumor
    const rumor = createMailRumor({
      senderPubkey,
      recipients,
      subject: options.subject,
      body: options.body,
      contentType: options.contentType,
      replyTo: options.replyTo,
      threadId: options.threadId,
    })

    // Wrap for all recipients + self-copy
    const allRecipientPubkeys = [
      ...toList,
      ...ccList,
      ...bccList,
    ].map(pubkey => ({ pubkey, relays: this.relays }))

    return wrapMailForRecipients(rumor, this.privkey, allRecipientPubkeys)
  }

  /**
   * Decrypt and parse a received gift wrap event.
   *
   * @param wrapEvent - A kind 1059 gift wrap event from a relay.
   * @returns The parsed mail message, or null if decryption failed.
   */
  async receive(wrapEvent: {
    id: string
    pubkey: string
    content: string
    kind: number
    created_at: number
    tags: string[][]
    sig: string
  }): Promise<ParsedMail | null> {
    if (!this.privkey) {
      throw new Error('Direct receive requires a private key.')
    }

    const result = await tryUnwrapMail(wrapEvent, this.privkey)
    if (!result) return null

    const parsed = parseMailRumor(result.rumor)

    // Build ParsedMail from the raw parse result
    const mail: ParsedMail = {
      id: wrapEvent.id,
      from: { pubkey: result.senderPubkey },
      to: parsed.to
        .filter(r => r.role === 'to')
        .map(r => ({ pubkey: r.pubkey, relayHint: r.relay })),
      cc: parsed.to
        .filter(r => r.role === 'cc')
        .map(r => ({ pubkey: r.pubkey, relayHint: r.relay })),
      subject: parsed.subject,
      body: parsed.body,
      contentType: parsed.contentType as ParsedMail['contentType'],
      attachments: parsed.attachments,
      threadId: parsed.threadId,
      replyTo: parsed.replyTo,
      cashuPostage: parsed.cashuPostage,
      createdAt: result.rumor.created_at,
      receivedAt: wrapEvent.created_at,
    }

    return mail
  }

  /**
   * Evaluate the spam tier for a received mail message.
   *
   * @param mail - A parsed mail message (from receive()).
   * @param contactList - Set of pubkeys the user follows.
   */
  evaluateSpam(
    mail: ParsedMail,
    contactList: Set<string>,
  ) {
    return evaluateSpamTier(mail.from.pubkey, contactList, mail.cashuPostage, this.spamPolicy)
  }

  /**
   * Build a conversation thread from a set of parsed messages.
   *
   * @param messages - Array of parsed mail messages.
   * @returns Array of root thread nodes.
   */
  buildThread(messages: ParsedMail[]) {
    return buildThread(messages)
  }

  /**
   * Group messages by thread and return them as a map.
   *
   * @param messages - Array of parsed mail messages.
   * @returns Map from thread root ID to messages in that thread.
   */
  groupByThread(messages: ParsedMail[]) {
    return groupByThread(messages)
  }

  /**
   * Flatten a thread tree into chronological order.
   *
   * @param messages - Array of parsed mail messages.
   * @returns Flat array in conversation order.
   */
  flattenThread(messages: ParsedMail[]) {
    const roots = buildThread(messages)
    return flattenThread(roots)
  }

  /**
   * Mark a message as read in the local mailbox state.
   *
   * @param eventId - The gift wrap event ID.
   */
  markRead(eventId: string): void {
    this.state = stateMarkRead(this.state, eventId)
  }

  /**
   * Get the current mailbox state.
   */
  getState(): MailboxState {
    return this.state
  }

  /**
   * Merge remote mailbox state into the local state.
   *
   * @param remote - A MailboxState from a kind 10099 event.
   */
  mergeState(remote: MailboxState): void {
    this.state = mergeStates(this.state, remote)
  }
}

// ── Internal helpers ────────────────────────────────────────────────────────

/**
 * Convert a hex string to Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16)
    if (isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i}`)
    }
    bytes[i / 2] = byte
  }
  return bytes
}

/**
 * Normalize a recipient input (string or string array) to a string array.
 */
function normalizeRecipients(input: string | string[] | undefined): string[] {
  if (!input) return []
  if (typeof input === 'string') return [input]
  return input
}
