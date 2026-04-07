// ─── NOSTR Mail Protocol — Mailbox State ─────────────────────────────────────
// G-Set reads (append-only), LWW flags/folders, serialization for kind 30099.
// State is partitioned by month (d tag = YYYY-MM). IDs are message-id values.

import type { MailboxState } from './types.js'

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
 * Note: Callers SHOULD reject state events with created_at more than
 * 1 hour in the future (prevents timestamp manipulation attacks).
 *
 $1 (CRDT merge).
 *
 * - **reads**: G-Set union (append-only, any read from either state persists).
 * - **deleted**: G-Set union (same as reads).
 * - **flags**: Union of flag arrays per event ID (both states' flags are kept).
 * - **folders**: LWW — takes values from `b` for conflicts (assuming `b` is newer).
 *
 * In practice, the caller should ensure `b` is the more recent state
 * (e.g., from a newer kind 30099 event) for correct LWW resolution.
 *
 * @param a - The older (or local) mailbox state.
 * @param b - The newer (or remote) mailbox state.
 * @returns Merged mailbox state.
 */
export function mergeStates(a: MailboxState, b: MailboxState): MailboxState {
  // G-Set union for reads
  const reads = new Set<string>([...a.reads, ...b.reads])

  // G-Set union for deleted
  const deleted = new Set<string>([...a.deleted, ...b.deleted])

  // Merge flags: union of flag arrays per event ID
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

  // LWW merge for folders: start with a, overlay b (b wins on conflict)
  const folders = new Map<string, string>([...a.folders, ...b.folders])

  return { reads, flags, folders, deleted }
}

/**
 * Serialize mailbox state to tags for a kind 30099 event.
 *
 * Tag format:
 * - `["read", eventId]` for each read message
 * - `["flag", eventId, flag1, flag2, ...]` for flagged messages
 * - `["folder", eventId, folderName]` for folder assignments
 * - `["deleted", eventId]` for deleted messages
 *
 * @param state - The mailbox state to serialize.
 * @param partition - Month partition in YYYY-MM format (e.g., '2026-04').
 * @returns Tags array for a kind 30099 addressable event.
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
 * Deserialize a kind 30099 event's tags to mailbox state.
 *
 * @param tags - Tags from a kind 30099 event.
 * @returns Reconstructed MailboxState. The `d` tag is ignored (partition info).
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
