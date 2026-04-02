// ─── NOSTR Mail Protocol — Type Definitions ────────────────────────────────
// All types for kind 1111 mail events, anti-spam, state sync, and threading.

/** A NOSTR Mail message (kind 1111 rumor — unsigned). */
export interface MailMessage {
  kind: 1111
  pubkey: string
  created_at: number
  tags: string[][]
  content: string
}

/** Parsed mail message (after decryption and tag extraction). */
export interface ParsedMail {
  /** Event ID of the gift wrap envelope. */
  id: string
  /** Sender identity. */
  from: MailIdentity
  /** TO recipients. */
  to: MailIdentity[]
  /** CC recipients. */
  cc: MailIdentity[]
  /** Mail subject line. */
  subject: string
  /** Message body content. */
  body: string
  /** MIME content type of the body. */
  contentType: 'text/plain' | 'text/markdown' | 'text/html'
  /** File attachments (Blossom references). */
  attachments: MailAttachment[]
  /** Root event ID for threading. */
  threadId?: string
  /** Parent event ID for reply chains. */
  replyTo?: string
  /** Anti-spam Cashu postage token, if present. */
  cashuPostage?: CashuPostage
  /** Timestamp from the inner rumor. */
  createdAt: number
  /** Timestamp when the wrap was received/processed. */
  receivedAt: number
}

/** A user identity (pubkey + optional metadata). */
export interface MailIdentity {
  pubkey: string
  /** Display name from kind 0 profile. */
  name?: string
  /** NIP-05 identifier (user@domain). */
  nip05?: string
  /** Preferred relay for reaching this user. */
  relayHint?: string
}

/** File attachment reference (Blossom-backed). */
export interface MailAttachment {
  /** Blossom SHA-256 hash of the file. */
  hash: string
  /** Original filename. */
  filename: string
  /** MIME type. */
  mimeType: string
  /** File size in bytes. */
  size: number
  /** NIP-44 symmetric encryption key (hex), if the file is encrypted. */
  encryptionKey?: string
  /** Blossom server URLs where the file can be retrieved. */
  blossomUrls: string[]
}

/** Cashu postage token for anti-spam (always NUT-11 P2PK locked). */
export interface CashuPostage {
  /** Serialized NUT-00 Cashu token. */
  token: string
  /** Mint URL. */
  mint: string
  /** Amount in satoshis. */
  amount: number
  /** Whether token is P2PK locked to the recipient. */
  p2pk: boolean
}

/** Anti-spam tier evaluation result. */
export interface SpamTier {
  /** Tier number: 0 = most trusted, 5 = unknown/rejected. */
  tier: 0 | 1 | 2 | 3 | 4 | 5
  /** Human-readable reason for the tier classification. */
  reason: string
  /** Recommended action based on the tier. */
  action: 'inbox' | 'quarantine' | 'reject'
}

/** Anti-spam policy (published as kind 10097). */
export interface SpamPolicy {
  /** Whether contacts (kind 3 follows) bypass all checks. */
  contactsFree: boolean
  /** Whether NIP-05 verified senders bypass PoW/Cashu checks. */
  nip05Free: boolean
  /** Minimum NIP-13 PoW difficulty bits required. */
  powMinBits: number
  /** Minimum Cashu postage amount in satoshis. */
  cashuMinSats: number
  /** Accepted Cashu mint URLs. */
  acceptedMints: string[]
  /** Action for messages that pass no tier: quarantine or reject. */
  unknownAction: 'quarantine' | 'reject'
}

/** Mailbox state for read/flag/folder/delete tracking (kind 10099). */
export interface MailboxState {
  /** G-Set of event IDs marked as read (append-only, irreversible). */
  reads: Set<string>
  /** Event ID → array of flag names (starred, important, etc.). */
  flags: Map<string, string[]>
  /** Event ID → folder name. */
  folders: Map<string, string>
  /** Event IDs marked as deleted. */
  deleted: Set<string>
}

/** Options for sending mail via the high-level API. */
export interface SendOptions {
  /** Recipient(s): NIP-05 addresses or hex pubkeys. */
  to: string | string[]
  /** CC recipient(s). */
  cc?: string | string[]
  /** BCC recipient(s) — not visible to other recipients. */
  bcc?: string | string[]
  /** Mail subject line. */
  subject: string
  /** Message body. */
  body: string
  /** Content type of the body (default: text/plain). */
  contentType?: 'text/plain' | 'text/markdown' | 'text/html'
  /** File attachments to include. */
  attachments?: AttachmentInput[]
  /** Event ID of the message being replied to. */
  replyTo?: string
  /** Root event ID of the thread. */
  threadId?: string
}

/** Raw attachment input for sending. */
export interface AttachmentInput {
  filename: string
  data: Uint8Array
  mimeType: string
}

/** Configuration for a NostrMail instance. */
export interface NostrMailConfig {
  /** Hex-encoded private key (direct signing mode). */
  privateKey?: string
  /** External signer (NIP-07/NIP-46 compatible). */
  signer?: Signer
  /** Default relay URLs for publishing. */
  relays?: string[]
  /** Kind 10050 inbox relay URLs. */
  inboxRelays?: string[]
  /** Anti-spam policy overrides. */
  spamPolicy?: Partial<SpamPolicy>
}

/** Signer interface compatible with NIP-07 (window.nostr) and NIP-46. */
export interface Signer {
  getPublicKey(): Promise<string>
  signEvent(event: unknown): Promise<unknown>
  nip44: {
    encrypt(pubkey: string, plaintext: string): Promise<string>
    decrypt(pubkey: string, ciphertext: string): Promise<string>
  }
}

/** Thread node for conversation tree display. */
export interface ThreadNode {
  message: ParsedMail
  children: ThreadNode[]
  parent?: ThreadNode
}
