import { describe, it, expect } from 'vitest'
import {
  createMailboxState,
  markRead,
  isRead,
  getFlags,
  toggleFlag,
  moveToFolder,
  getFolder,
  markDeleted,
  mergeStates,
  stateToTags,
  tagsToState,
} from '../src/state.js'

describe('mailbox state — reads (G-Set)', () => {
  it('marks a message as read', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = markRead(state, eventId)

    expect(isRead(state, eventId)).toBe(true)
  })

  it('marks a message as read twice (idempotent)', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = markRead(state, eventId)
    state = markRead(state, eventId)

    expect(isRead(state, eventId)).toBe(true)
    expect(state.reads.size).toBe(1)
  })

  it('cannot "unread" a message (G-Set is append-only, merge restores)', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = markRead(state, eventId)

    // Capture a snapshot of the state that has the read
    const snapshot = state

    // Simulate a separate replica that has NOT read the message
    const otherReplica = createMailboxState()

    // Merging with the snapshot should preserve the read status
    const merged = mergeStates(otherReplica, snapshot)
    expect(isRead(merged, eventId)).toBe(true)

    // Even merging an empty state on top of a read state preserves reads
    const mergedReverse = mergeStates(snapshot, otherReplica)
    expect(isRead(mergedReverse, eventId)).toBe(true)
  })

  it('unread messages return false', () => {
    const state = createMailboxState()

    expect(isRead(state, 'nonexistent')).toBe(false)
  })

  it('tracks multiple reads independently', () => {
    let state = createMailboxState()
    const id1 = 'aaaa000000000000000000000000000000000000000000000000000000000001'
    const id2 = 'aaaa000000000000000000000000000000000000000000000000000000000002'
    const id3 = 'aaaa000000000000000000000000000000000000000000000000000000000003'

    state = markRead(state, id1)
    state = markRead(state, id2)

    expect(isRead(state, id1)).toBe(true)
    expect(isRead(state, id2)).toBe(true)
    expect(isRead(state, id3)).toBe(false)
    expect(state.reads.size).toBe(2)
  })

  it('markRead returns a new state object (immutable)', () => {
    const state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    const newState = markRead(state, eventId)

    expect(newState).not.toBe(state)
    expect(isRead(newState, eventId)).toBe(true)
    expect(isRead(state, eventId)).toBe(false) // original unchanged
  })
})

describe('mailbox state — flags', () => {
  it('toggles a flag on', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = toggleFlag(state, eventId, 'starred')

    expect(getFlags(state, eventId)).toContain('starred')
  })

  it('toggles a flag off', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = toggleFlag(state, eventId, 'starred') // on
    state = toggleFlag(state, eventId, 'starred') // off

    expect(getFlags(state, eventId)).not.toContain('starred')
  })

  it('returns empty array for unflagged messages', () => {
    const state = createMailboxState()

    expect(getFlags(state, 'nonexistent')).toEqual([])
  })

  it('toggles one flag without affecting others', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = toggleFlag(state, eventId, 'starred')
    state = toggleFlag(state, eventId, 'important')
    // Now has ['starred', 'important']

    state = toggleFlag(state, eventId, 'starred') // remove starred

    expect(getFlags(state, eventId)).not.toContain('starred')
    expect(getFlags(state, eventId)).toContain('important')
  })

  it('multiple flags can be set on the same message', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = toggleFlag(state, eventId, 'starred')
    state = toggleFlag(state, eventId, 'important')
    state = toggleFlag(state, eventId, 'urgent')

    const flags = getFlags(state, eventId)
    expect(flags).toContain('starred')
    expect(flags).toContain('important')
    expect(flags).toContain('urgent')
    expect(flags).toHaveLength(3)
  })

  it('toggleFlag returns a new state object (immutable)', () => {
    const state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    const newState = toggleFlag(state, eventId, 'starred')

    expect(newState).not.toBe(state)
    expect(getFlags(newState, eventId)).toContain('starred')
    expect(getFlags(state, eventId)).toEqual([]) // original unchanged
  })
})

describe('mailbox state — folders', () => {
  it('moves a message to a folder', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = moveToFolder(state, eventId, 'archive')

    expect(getFolder(state, eventId)).toBe('archive')
  })

  it('moving to a new folder replaces the old one', () => {
    let state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    state = moveToFolder(state, eventId, 'inbox')
    state = moveToFolder(state, eventId, 'archive')

    expect(getFolder(state, eventId)).toBe('archive')
  })

  it('returns undefined for messages without a folder', () => {
    const state = createMailboxState()

    expect(getFolder(state, 'nonexistent')).toBeUndefined()
  })

  it('moveToFolder returns a new state object (immutable)', () => {
    const state = createMailboxState()
    const eventId = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    const newState = moveToFolder(state, eventId, 'archive')

    expect(newState).not.toBe(state)
    expect(getFolder(newState, eventId)).toBe('archive')
    expect(getFolder(state, eventId)).toBeUndefined() // original unchanged
  })
})

describe('mailbox state — merge (CRDT)', () => {
  it('merges two states — reads are unioned (G-Set)', () => {
    let stateA = createMailboxState()
    let stateB = createMailboxState()

    stateA = markRead(stateA, 'msg1')
    stateA = markRead(stateA, 'msg2')
    stateB = markRead(stateB, 'msg2')
    stateB = markRead(stateB, 'msg3')

    const merged = mergeStates(stateA, stateB)

    expect(isRead(merged, 'msg1')).toBe(true)
    expect(isRead(merged, 'msg2')).toBe(true)
    expect(isRead(merged, 'msg3')).toBe(true)
    expect(merged.reads.size).toBe(3)
  })

  it('merges flags — union of flag arrays per event ID', () => {
    let stateA = createMailboxState()
    let stateB = createMailboxState()

    stateA = toggleFlag(stateA, 'msg1', 'starred')
    stateB = toggleFlag(stateB, 'msg1', 'important')
    stateB = toggleFlag(stateB, 'msg2', 'urgent')

    const merged = mergeStates(stateA, stateB)

    const msg1Flags = getFlags(merged, 'msg1')
    expect(msg1Flags).toContain('starred')
    expect(msg1Flags).toContain('important')
    expect(msg1Flags).toHaveLength(2)

    expect(getFlags(merged, 'msg2')).toEqual(['urgent'])
  })

  it('merges folders — second state takes precedence (LWW)', () => {
    let stateA = createMailboxState()
    let stateB = createMailboxState()

    stateA = moveToFolder(stateA, 'msg1', 'inbox')
    stateB = moveToFolder(stateB, 'msg1', 'archive')

    const merged = mergeStates(stateA, stateB)

    expect(getFolder(merged, 'msg1')).toBe('archive')
  })

  it('merges deleted sets — union', () => {
    let stateA = createMailboxState()
    let stateB = createMailboxState()

    stateA = markDeleted(stateA, 'msg1')
    stateB = markDeleted(stateB, 'msg2')

    const merged = mergeStates(stateA, stateB)

    expect(merged.deleted.has('msg1')).toBe(true)
    expect(merged.deleted.has('msg2')).toBe(true)
    expect(merged.deleted.size).toBe(2)
  })

  it('merged state is a new object (no mutation of originals)', () => {
    let stateA = createMailboxState()
    let stateB = createMailboxState()

    stateA = markRead(stateA, 'msg1')
    stateB = markRead(stateB, 'msg2')

    const merged = mergeStates(stateA, stateB)

    // Original states are unchanged
    expect(stateA.reads.size).toBe(1)
    expect(stateB.reads.size).toBe(1)
    expect(merged.reads.size).toBe(2)

    // Merged is a distinct object
    expect(merged.reads).not.toBe(stateA.reads)
    expect(merged.reads).not.toBe(stateB.reads)
  })
})

describe('mailbox state — serialization', () => {
  it('serializes to tags and back (round-trip)', () => {
    let state = createMailboxState()

    state = markRead(state, 'msg1')
    state = markRead(state, 'msg2')
    state = toggleFlag(state, 'msg1', 'starred')
    state = toggleFlag(state, 'msg1', 'important')
    state = moveToFolder(state, 'msg2', 'archive')
    state = markDeleted(state, 'msg3')

    const tags = stateToTags(state)
    const restored = tagsToState(tags)

    expect(isRead(restored, 'msg1')).toBe(true)
    expect(isRead(restored, 'msg2')).toBe(true)
    expect(isRead(restored, 'msg3')).toBe(false) // deleted, not read
    expect(getFlags(restored, 'msg1')).toContain('starred')
    expect(getFlags(restored, 'msg1')).toContain('important')
    expect(getFolder(restored, 'msg2')).toBe('archive')
    expect(restored.deleted.has('msg3')).toBe(true)
  })

  it('serializes empty state', () => {
    const state = createMailboxState()

    const tags = stateToTags(state)
    expect(tags).toHaveLength(0)

    const restored = tagsToState(tags)
    expect(restored.reads.size).toBe(0)
    expect(restored.flags.size).toBe(0)
    expect(restored.folders.size).toBe(0)
    expect(restored.deleted.size).toBe(0)
  })

  it('produces correct tag format', () => {
    let state = createMailboxState()

    state = markRead(state, 'ev1')
    state = toggleFlag(state, 'ev2', 'starred')
    state = toggleFlag(state, 'ev2', 'important')
    state = moveToFolder(state, 'ev3', 'sent')
    state = markDeleted(state, 'ev4')

    const tags = stateToTags(state)

    expect(tags).toContainEqual(['read', 'ev1'])
    expect(tags).toContainEqual(['flag', 'ev2', 'starred', 'important'])
    expect(tags).toContainEqual(['folder', 'ev3', 'sent'])
    expect(tags).toContainEqual(['deleted', 'ev4'])
  })

  it('deserialization ignores unknown tag types', () => {
    const tags = [
      ['read', 'msg1'],
      ['unknown', 'data'],
      ['flag', 'msg1', 'starred'],
    ]

    const state = tagsToState(tags)

    expect(isRead(state, 'msg1')).toBe(true)
    expect(getFlags(state, 'msg1')).toEqual(['starred'])
  })

  it('deserialization ignores malformed tags', () => {
    const tags = [
      ['read'], // missing event ID
      ['flag'], // missing event ID
      ['folder', 'msg1'], // missing folder name
      ['read', 'valid1'],
    ]

    const state = tagsToState(tags)

    // Only the valid tag should be processed
    expect(state.reads.size).toBe(1)
    expect(isRead(state, 'valid1')).toBe(true)
  })
})
