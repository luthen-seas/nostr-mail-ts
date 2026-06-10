// ─── NOSTR Mail Protocol — Mailbox State ─────────────────────────────────────
// G-Set reads (append-only), LWW flags/folders, serialization for kind 30099.
// State is partitioned by month (d tag = YYYY-MM). IDs are message-id values.
//
// Kind 30099 events carry state as an encrypted JSON payload in the content
// field (NIP-44 self-encrypted). The only visible tag is ["d", "YYYY-MM"].

import * as nip44 from 'nostr-tools/nip44'
import type { MailboxState, MailMessage } from './types.js'

/** JSON schema for the encrypted kind 30099 payload. */
export interface StatePayload {
  read: string[]
  flag: Record<string, string[]>
  folder: Record<string, string>
  deleted: string[]
}

/**
 * Maximum acceptable clock skew, in seconds, for an incoming kind-30099 event's
 * `created_at` (F-STATE-01 / FINDING-007). Events dated further than this into
 * the future are rejected so a malicious/relay-injected far-future event cannot
 * win folder LWW forever.
 */
export const STATE_MAX_FUTURE_SKEW_SECONDS = 3600

/** Bounds on a decoded state payload to prevent unbounded-growth DoS (F-STATE-02). */
export const STATE_MAX_IDS_PER_FIELD = 100_000
export const STATE_MAX_FLAGS_PER_ID = 32
/** Max length of a single id / flag string (bounds per-entry size). */
export const STATE_MAX_ID_LENGTH = 128

/**
 * Returns true if a kind-30099 event timestamp is acceptable for ingestion.
 * Callers MUST reject events for which this returns false before merging.
 */
export function isStateTimestampAcceptable(
  createdAt: number,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  return Number.isFinite(createdAt) && createdAt <= nowSeconds + STATE_MAX_FUTURE_SKEW_SECONDS
}

/**
 * Compare two (createdAt, eventId) clocks. Returns >0 if X is preferred over Y.
 * X is preferred when it has the greater `createdAt`, or — on a tie — the
 * lexicographically LOWER `eventId` (NIP-01 replaceable-event rule, DEC-020).
 * Equal clocks return 0.
 */
function compareClock(
  xTs: number | undefined,
  xId: string | undefined,
  yTs: number | undefined,
  yId: string | undefined,
): number {
  const tx = xTs ?? 0
  const ty = yTs ?? 0
  if (tx !== ty) return tx - ty
  const ix = xId ?? ''
  const iy = yId ?? ''
  if (ix === iy) return 0
  return ix < iy ? 1 : -1
}

/**
 * Create an empty mailbox state.
 *
 * @returns A fresh MailboxState with empty collections.
 */
export function createMailboxState(): MailboxState {
  return {
    reads: new Set<string>(),
    flags: new Map<string, string[]>(),
    folders: new Map<string, string>(),
    deleted: new Set<string>(),
  }
}

/**
 * Mark a message as read (G-Set: append-only, irreversible).
 *
 * The read set is a Grow-only Set (G-Set). Once a message
 * is marked read, it cannot be marked unread. This is a CRDT that
 * converges naturally across devices — any device marking a message
 * read will propagate to all other devices on merge.
 *
 * @param state - Current mailbox state.
 * @param messageId - The message-id to mark as read.
 * @returns Updated mailbox state (new object, original not mutated).
 */
export function markRead(state: MailboxState, eventId: string): MailboxState {
  const newReads = new Set(state.reads)
  newReads.add(eventId)
  return { ...state, reads: newReads }
}

/**
 * Check if a message has been marked as read.
 *
 * @param state - Current mailbox state.
 * @param messageId - The message-id to check.
 * @returns True if the message is in the read G-Set.
 */
export function isRead(state: MailboxState, eventId: string): boolean {
  return state.reads.has(eventId)
}

/**
 * Toggle a flag on a message (LWW semantics).
 *
 * If the flag is present, it is removed. If absent, it is added.
 * Common flags: "starred", "important", "flagged".
 *
 * @param state - Current mailbox state.
 * @param eventId - The gift wrap event ID to toggle the flag on.
 * @param flag - The flag name to toggle.
 * @returns Updated mailbox state (new object, original not mutated).
 */
export function toggleFlag(
  state: MailboxState,
  eventId: string,
  flag: string,
): MailboxState {
  const newFlags = new Map(state.flags)
  const current = newFlags.get(eventId) ?? []

  if (current.includes(flag)) {
    // Remove the flag
    const updated = current.filter(f => f !== flag)
    if (updated.length === 0) {
      newFlags.delete(eventId)
    } else {
      newFlags.set(eventId, updated)
    }
  } else {
    // Add the flag
    newFlags.set(eventId, [...current, flag])
  }

  return { ...state, flags: newFlags }
}

/**
 * Get the flags currently set on a message.
 *
 * @param state - Current mailbox state.
 * @param eventId - The gift wrap event ID.
 * @returns Array of flag names, or empty array if none.
 */
export function getFlags(state: MailboxState, eventId: string): string[] {
  return state.flags.get(eventId) ?? []
}

/**
 * Move a message to a folder (LWW semantics).
 *
 * Each message can be in exactly one folder. Moving to a new folder
 * replaces the old assignment. Standard folders: "inbox", "sent",
 * "drafts", "archive", "trash".
 *
 * @param state - Current mailbox state.
 * @param eventId - The gift wrap event ID to move.
 * @param folder - The target folder name.
 * @returns Updated mailbox state (new object, original not mutated).
 */
export function moveToFolder(
  state: MailboxState,
  eventId: string,
  folder: string,
): MailboxState {
  const newFolders = new Map(state.folders)
  newFolders.set(eventId, folder)
  return { ...state, folders: newFolders }
}

/**
 * Get the folder a message is currently in.
 *
 * @param state - Current mailbox state.
 * @param eventId - The gift wrap event ID.
 * @returns The folder name, or undefined if not assigned.
 */
export function getFolder(state: MailboxState, eventId: string): string | undefined {
  return state.folders.get(eventId)
}

/**
 * Mark a message as deleted.
 *
 * @param state - Current mailbox state.
 * @param eventId - The gift wrap event ID to mark deleted.
 * @returns Updated mailbox state (new object, original not mutated).
 */
export function markDeleted(
  state: MailboxState,
  eventId: string,
): MailboxState {
  const newDeleted = new Set(state.deleted)
  newDeleted.add(eventId)
  return { ...state, deleted: newDeleted }
}

/**
 * Merge two mailbox states (CRDT merge).
 *
 * - **reads / deleted**: G-Set union (append-only; order-independent).
 * - **flags**: union of flag arrays per id (order-independent).
 * - **folders**: true LWW (F-STATE-01 / DEC-020). For a key present in both
 *   states the value from the state with the greater `(createdAt, eventId)`
 *   clock wins; ties break on the lexicographically greater `eventId`. This is
 *   deterministic regardless of argument order — two devices merging the same
 *   pair in opposite order converge to the same result.
 *
 * Ingestion of a remote kind-30099 event MUST first reject future-dated events
 * via {@link isStateTimestampAcceptable}; otherwise a far-future event could
 * win folder LWW permanently.
 *
 * @param a - A mailbox state (e.g. local).
 * @param b - Another mailbox state (e.g. remote).
 * @returns Merged mailbox state. Its clock is the newer of the two inputs'.
 */
export function mergeStates(a: MailboxState, b: MailboxState): MailboxState {
  const reads = new Set<string>([...a.reads, ...b.reads])
  const deleted = new Set<string>([...a.deleted, ...b.deleted])

  const flags = new Map<string, string[]>()
  const allFlagIds = new Set([...a.flags.keys(), ...b.flags.keys()])
  for (const id of allFlagIds) {
    const aFlags = a.flags.get(id) ?? []
    const bFlags = b.flags.get(id) ?? []
    const merged = [...new Set([...aFlags, ...bFlags])]
    if (merged.length > 0) {
      flags.set(id, merged)
    }
  }

  // Folders: deterministic LWW. On conflict the winner's value is taken. Ties
  // (including the no-metadata legacy case where callers pass the newer state
  // as `b`) resolve in favor of `b`.
  const bWins = compareClock(b.createdAt, b.eventId, a.createdAt, a.eventId) >= 0
  const folders = new Map<string, string>()
  const allFolderIds = new Set([...a.folders.keys(), ...b.folders.keys()])
  for (const id of allFolderIds) {
    const inA = a.folders.has(id)
    const inB = b.folders.has(id)
    if (inA && inB) {
      folders.set(id, (bWins ? b.folders.get(id) : a.folders.get(id))!)
    } else if (inA) {
      folders.set(id, a.folders.get(id)!)
    } else {
      folders.set(id, b.folders.get(id)!)
    }
  }

  // The merged state's clock is the newer of the two.
  const newer = compareClock(a.createdAt, a.eventId, b.createdAt, b.eventId) >= 0 ? a : b

  return { reads, flags, folders, deleted, createdAt: newer.createdAt, eventId: newer.eventId }
}

/**
 * Convert mailbox state to the JSON payload for kind 30099 content.
 *
 * The caller is responsible for NIP-44 encrypting the returned JSON string
 * to the user's own public key before publishing.
 *
 * @param state - The mailbox state to serialize.
 * @returns JSON payload object matching the StatePayload schema.
 */
export function stateToPayload(state: MailboxState): StatePayload {
  // F-DET-01: emit ids and flag arrays in sorted order so the serialized bytes
  // are deterministic and byte-identical to the Go implementation (AMEND-008).
  const flag: Record<string, string[]> = {}
  for (const id of [...state.flags.keys()].sort()) {
    const flagList = state.flags.get(id)!
    if (flagList.length > 0) {
      flag[id] = [...flagList].sort()
    }
  }

  const folder: Record<string, string> = {}
  for (const id of [...state.folders.keys()].sort()) {
    folder[id] = state.folders.get(id)!
  }

  return {
    read: [...state.reads].sort(),
    flag,
    folder,
    deleted: [...state.deleted].sort(),
  }
}

/**
 * Parse a decrypted JSON payload into mailbox state.
 *
 * The caller is responsible for NIP-44 decrypting the kind 30099 content
 * field before passing the plaintext JSON string here.
 *
 * @param payload - Parsed StatePayload object.
 * @returns Reconstructed MailboxState.
 */
export function payloadToState(payload: StatePayload): MailboxState {
  const state = createMailboxState()

  // F-STATE-02: bound element counts and validate the id format so a malformed
  // or hostile payload cannot grow state unboundedly (it would then be
  // re-published forever via the G-Set union) or inject junk ids.
  const validId = (id: unknown): id is string =>
    typeof id === 'string' && id.length > 0 && id.length <= STATE_MAX_ID_LENGTH

  if (Array.isArray(payload.read)) {
    for (const id of payload.read.slice(0, STATE_MAX_IDS_PER_FIELD)) {
      if (validId(id)) state.reads.add(id)
    }
  }

  if (payload.flag && typeof payload.flag === 'object') {
    let count = 0
    for (const [id, flagList] of Object.entries(payload.flag)) {
      if (count++ >= STATE_MAX_IDS_PER_FIELD) break
      if (validId(id) && Array.isArray(flagList) && flagList.length > 0) {
        const flags = flagList.filter((f): f is string => typeof f === 'string').slice(0, STATE_MAX_FLAGS_PER_ID)
        if (flags.length > 0) state.flags.set(id, flags)
      }
    }
  }

  if (payload.folder && typeof payload.folder === 'object') {
    let count = 0
    for (const [id, folder] of Object.entries(payload.folder)) {
      if (count++ >= STATE_MAX_IDS_PER_FIELD) break
      if (validId(id) && typeof folder === 'string') {
        state.folders.set(id, folder)
      }
    }
  }

  if (Array.isArray(payload.deleted)) {
    for (const id of payload.deleted.slice(0, STATE_MAX_IDS_PER_FIELD)) {
      if (validId(id)) state.deleted.add(id)
    }
  }

  return state
}

/**
 * Serialize mailbox state for a kind 30099 event.
 *
 * Returns the tags array (containing only the d tag) and the JSON content
 * string. The caller MUST NIP-44 encrypt the content string to the user's
 * own public key before publishing.
 *
 * @param state - The mailbox state to serialize.
 * @param partition - Month partition in YYYY-MM format (e.g., '2026-04').
 * @returns Object with `tags` (string[][]) and `content` (JSON string).
 */
export function serializeState(
  state: MailboxState,
  partition: string,
): { tags: string[][]; content: string } {
  return {
    tags: [['d', partition]],
    content: JSON.stringify(stateToPayload(state)),
  }
}

/**
 * Deserialize a kind 30099 event's decrypted content into mailbox state.
 *
 * The caller MUST NIP-44 decrypt the content field before passing it here.
 *
 * @param content - Decrypted JSON string from the kind 30099 content field.
 * @returns Reconstructed MailboxState.
 */
export function deserializeState(content: string): MailboxState {
  const payload: StatePayload = JSON.parse(content)
  return payloadToState(payload)
}

/**
 * Serialize and NIP-44-encrypt mailbox state for a kind 30099 event.
 *
 * Per DEC-013, the state payload is encrypted to the user's own pubkey
 * (self-encryption) and stored in the event's `content` field. The only
 * visible tag is `["d", "YYYY-MM"]`.
 *
 * @param state - The mailbox state to serialize.
 * @param partition - Month partition in YYYY-MM format (e.g., '2026-04').
 * @param privkey - The user's 32-byte private key (used for self-ECDH).
 * @param ownPubkey - The user's hex public key.
 * @returns Tags + encrypted content ready to sign and publish.
 */
export function serializeStateEncrypted(
  state: MailboxState,
  partition: string,
  privkey: Uint8Array,
  ownPubkey: string,
): { tags: string[][]; content: string } {
  const convKey = nip44.v2.utils.getConversationKey(privkey, ownPubkey)
  try {
    const plaintext = JSON.stringify(stateToPayload(state))
    return {
      tags: [['d', partition]],
      content: nip44.v2.encrypt(plaintext, convKey),
    }
  } finally {
    convKey.fill(0)
  }
}

/**
 * Decrypt and deserialize a kind 30099 event's encrypted content.
 *
 * @param eventContent - The event's `content` field (NIP-44 ciphertext).
 * @param privkey - The user's 32-byte private key.
 * @param ownPubkey - The user's hex public key.
 * @returns Reconstructed MailboxState.
 */
export function deserializeStateEncrypted(
  eventContent: string,
  privkey: Uint8Array,
  ownPubkey: string,
): MailboxState {
  const convKey = nip44.v2.utils.getConversationKey(privkey, ownPubkey)
  try {
    const plaintext = nip44.v2.decrypt(eventContent, convKey)
    return deserializeState(plaintext)
  } finally {
    convKey.fill(0)
  }
}

/**
 * Derive the kind 30099 partition tag value (`YYYY-MM`) from a rumor's
 * `created_at` timestamp in UTC. Per DEC-013, partition is the month the
 * rumor was first received; clients should use the rumor's timestamp, NOT
 * the wrap's randomized timestamp.
 */
export function partitionFor(rumor: MailMessage): string {
  const d = new Date(rumor.created_at * 1000)
  const yyyy = d.getUTCFullYear()
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0')
  return `${yyyy}-${mm}`
}

// ─── Legacy compatibility ───────────────────────────────────────────────────
// These functions support the old plaintext-tags format for migration from
// pre-encryption kind 30099 events.

/**
 * @deprecated Use serializeState() instead. This function produces plaintext
 * tags that leak mailbox state to relay operators.
 */
export function stateToTags(state: MailboxState, partition: string): string[][] {
  const tags: string[][] = [['d', partition]]

  for (const id of state.reads) {
    tags.push(['read', id])
  }

  for (const [id, flagList] of state.flags) {
    if (flagList.length > 0) {
      tags.push(['flag', id, ...flagList])
    }
  }

  for (const [id, folder] of state.folders) {
    tags.push(['folder', id, folder])
  }

  for (const id of state.deleted) {
    tags.push(['deleted', id])
  }

  return tags
}

/**
 * @deprecated Use deserializeState() instead. This function parses the old
 * plaintext-tags format.
 */
export function tagsToState(tags: string[][]): MailboxState {
  const state = createMailboxState()

  for (const tag of tags) {
    const key = tag[0]
    const eventId = tag[1]

    if (!key || !eventId) continue

    switch (key) {
      case 'read':
        state.reads.add(eventId)
        break
      case 'flag': {
        const flagNames = tag.slice(2)
        if (flagNames.length > 0) {
          state.flags.set(eventId, flagNames)
        }
        break
      }
      case 'folder': {
        const folder = tag[2]
        if (folder) {
          state.folders.set(eventId, folder)
        }
        break
      }
      case 'deleted':
        state.deleted.add(eventId)
        break
    }
  }

  return state
}
