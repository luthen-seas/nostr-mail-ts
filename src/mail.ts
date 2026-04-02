// ─── NOSTR Mail Protocol — Kind 1400 Event Creation & Parsing ─────────────────
// Creates and parses the inner rumor layer of a NOSTR Mail message.

import type { MailMessage, MailAttachment, CashuPostage } from './types.js'

/** Parameters for creating a kind 1400 mail rumor. */
export interface CreateMailRumorParams {
  /** Sender's hex public key. */
  senderPubkey: string
  /** List of recipients with roles. */
  recipients: Array<{ pubkey: string; relay?: string; role: 'to' | 'cc' | 'bcc' }>
  /** Mail subject line. */
  subject: string
  /** Message body content. */
  body: string
  /** Content type (default: text/plain). */
  contentType?: 'text/plain' | 'text/markdown' | 'text/html'
  /** File attachments (Blossom references). */
  attachments?: MailAttachment[]
  /** Cashu postage for anti-spam (P2PK required). */
  cashuPostage?: CashuPostage
  /** Event ID of the message being replied to. */
  replyTo?: string
  /** Relay hint for the replyTo event. */
  replyToRelay?: string
  /** Root event ID of the thread. */
  threadId?: string
  /** Relay hint for the threadId event. */
  threadIdRelay?: string
  /** Override timestamp (default: now). */
  createdAt?: number
}

/**
 * Create a kind 1400 mail rumor (unsigned event).
 *
 * This is the innermost layer of a NOSTR Mail message. It will be
 * sealed (kind 13) and gift-wrapped (kind 1059) before publication.
 *
 * Tags produced:
 * - `["p", pubkey, relay, role]` for each recipient
 * - `["subject", text]`
 * - `["content-type", mime]` if not text/plain
 * - `["reply", eventId, relay]` for reply threading
 * - `["thread", eventId, relay]` for root threading
 * - `["attachment", hash, filename, mime, size]` per file
 * - `["attachment-key", hash, hexKey]` for encrypted files
 * - `["blossom", ...urls]` deduplicated server list
 * - `["cashu", token]`, `["cashu-mint", url]`, `["cashu-amount", sats]`
 */
export function createMailRumor(params: CreateMailRumorParams): MailMessage {
  const tags: string[][] = []

  // Recipient tags — each gets ["p", pubkey, relay, role]
  for (const r of params.recipients) {
    tags.push(['p', r.pubkey, r.relay ?? '', r.role])
  }

  // Subject (required)
  tags.push(['subject', params.subject])

  // Content type — only tag if not the default text/plain
  if (params.contentType && params.contentType !== 'text/plain') {
    tags.push(['content-type', params.contentType])
  }

  // Threading tags
  if (params.replyTo) {
    tags.push(['reply', params.replyTo, params.replyToRelay ?? ''])
  }
  if (params.threadId) {
    tags.push(['thread', params.threadId, params.threadIdRelay ?? ''])
  }

  // Attachment tags
  if (params.attachments && params.attachments.length > 0) {
    for (const att of params.attachments) {
      tags.push([
        'attachment',
        att.hash,
        att.filename,
        att.mimeType,
        String(att.size),
      ])
      if (att.encryptionKey) {
        tags.push(['attachment-key', att.hash, att.encryptionKey])
      }
    }

    // Deduplicated Blossom server URLs
    const blossomUrls = new Set(params.attachments.flatMap(a => a.blossomUrls))
    if (blossomUrls.size > 0) {
      tags.push(['blossom', ...blossomUrls])
    }
  }

  // Cashu postage (P2PK locked to recipient)
  if (params.cashuPostage) {
    tags.push(['cashu', params.cashuPostage.token])
    tags.push(['cashu-mint', params.cashuPostage.mint])
    tags.push(['cashu-amount', String(params.cashuPostage.amount)])
  }

  return {
    kind: 1400,
    pubkey: params.senderPubkey,
    created_at: params.createdAt ?? Math.floor(Date.now() / 1000),
    tags,
    content: params.body,
  }
}

/** Parsed result from a kind 1400 rumor's tags. */
export interface ParsedMailRumor {
  from: string
  to: Array<{ pubkey: string; relay?: string; role: string }>
  subject: string
  body: string
  contentType: string
  attachments: MailAttachment[]
  cashuPostage?: CashuPostage
  replyTo?: string
  threadId?: string
}

/**
 * Parse a decrypted kind 1400 rumor back into structured data.
 *
 * Extracts all tag-encoded fields (recipients, subject, attachments,
 * threading, Cashu postage) from the raw rumor event.
 */
export function parseMailRumor(rumor: MailMessage): ParsedMailRumor {
  const recipients = rumor.tags
    .filter(t => t[0] === 'p')
    .map(t => ({
      pubkey: t[1] ?? '',
      relay: t[2] || undefined,
      role: t[3] || 'to',
    }))

  const subject = rumor.tags.find(t => t[0] === 'subject')?.[1] ?? ''
  const contentType =
    rumor.tags.find(t => t[0] === 'content-type')?.[1] ?? 'text/plain'
  const replyTo = rumor.tags.find(t => t[0] === 'reply')?.[1]
  const threadId = rumor.tags.find(t => t[0] === 'thread')?.[1]

  // Parse attachment tags
  const attachmentTags = rumor.tags.filter(t => t[0] === 'attachment')
  const keyTags = rumor.tags.filter(t => t[0] === 'attachment-key')
  const blossomTag = rumor.tags.find(t => t[0] === 'blossom')
  const blossomUrls = blossomTag ? blossomTag.slice(1) : []

  const attachments: MailAttachment[] = attachmentTags.map(t => {
    const hash = t[1] ?? ''
    const keyTag = keyTags.find(k => k[1] === hash)
    return {
      hash,
      filename: t[2] ?? '',
      mimeType: t[3] ?? 'application/octet-stream',
      size: parseInt(t[4] ?? '0', 10),
      encryptionKey: keyTag?.[2],
      blossomUrls,
    }
  })

  // Parse Cashu postage
  const cashuTag = rumor.tags.find(t => t[0] === 'cashu')
  const cashuMint = rumor.tags.find(t => t[0] === 'cashu-mint')
  const cashuAmount = rumor.tags.find(t => t[0] === 'cashu-amount')
  const cashuPostage: CashuPostage | undefined = cashuTag
    ? {
        token: cashuTag[1] ?? '',
        mint: cashuMint?.[1] ?? '',
        amount: parseInt(cashuAmount?.[1] ?? '0', 10),
        p2pk: true, // Always P2PK locked
      }
    : undefined

  return {
    from: rumor.pubkey,
    to: recipients,
    subject,
    body: rumor.content,
    contentType,
    attachments,
    cashuPostage,
    replyTo,
    threadId,
  }
}
