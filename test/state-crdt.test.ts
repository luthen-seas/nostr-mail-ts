// Regression tests for R4 mailbox-state CRDT fixes (F-STATE-01/02, F-DET-01).
import { describe, it, expect } from 'vitest'
import {
  createMailboxState,
  moveToFolder,
  mergeStates,
  getFolder,
  payloadToState,
  stateToPayload,
  isStateTimestampAcceptable,
  STATE_MAX_IDS_PER_FIELD,
  STATE_MAX_FUTURE_SKEW_SECONDS,
} from '../src/state.js'
import type { MailboxState } from '../src/types.js'

function withClock(s: MailboxState, createdAt: number, eventId: string): MailboxState {
  return { ...s, createdAt, eventId }
}

describe('F-STATE-01: deterministic folder LWW', () => {
  it('newer createdAt wins the folder conflict regardless of merge order', () => {
    let older = createMailboxState()
    older = moveToFolder(older, 'msg1', 'archive')
    older = withClock(older, 1000, 'aaaa')

    let newer = createMailboxState()
    newer = moveToFolder(newer, 'msg1', 'inbox')
    newer = withClock(newer, 2000, 'bbbb')

    expect(getFolder(mergeStates(older, newer), 'msg1')).toBe('inbox')
    expect(getFolder(mergeStates(newer, older), 'msg1')).toBe('inbox')
  })

  it('equal createdAt breaks ties by lexicographically lower eventId (NIP-01/DEC-020)', () => {
    let a = moveToFolder(createMailboxState(), 'msg1', 'archive')
    a = withClock(a, 1000, 'aaaa') // lower id wins
    let b = moveToFolder(createMailboxState(), 'msg1', 'trash')
    b = withClock(b, 1000, 'bbbb')

    expect(getFolder(mergeStates(a, b), 'msg1')).toBe('archive')
    expect(getFolder(mergeStates(b, a), 'msg1')).toBe('archive')
  })

  it('non-conflicting folder keys are unioned', () => {
    const a = withClock(moveToFolder(createMailboxState(), 'm1', 'archive'), 1000, 'a')
    const b = withClock(moveToFolder(createMailboxState(), 'm2', 'trash'), 2000, 'b')
    const merged = mergeStates(a, b)
    expect(getFolder(merged, 'm1')).toBe('archive')
    expect(getFolder(merged, 'm2')).toBe('trash')
  })
})

describe('F-STATE-01: future-date rejection helper', () => {
  it('accepts now and recent past', () => {
    const now = 1_000_000
    expect(isStateTimestampAcceptable(now, now)).toBe(true)
    expect(isStateTimestampAcceptable(now - 86400, now)).toBe(true)
    expect(isStateTimestampAcceptable(now + STATE_MAX_FUTURE_SKEW_SECONDS, now)).toBe(true)
  })
  it('rejects far-future timestamps', () => {
    const now = 1_000_000
    expect(isStateTimestampAcceptable(now + STATE_MAX_FUTURE_SKEW_SECONDS + 1, now)).toBe(false)
    expect(isStateTimestampAcceptable(now + 10 * 365 * 86400, now)).toBe(false)
  })
})

describe('F-STATE-02: payload ingestion bounds', () => {
  it('caps the number of ingested read ids', () => {
    const huge = Array.from({ length: STATE_MAX_IDS_PER_FIELD + 50 }, (_, i) => `id${i}`)
    const state = payloadToState({ read: huge, flag: {}, folder: {}, deleted: [] })
    expect(state.reads.size).toBeLessThanOrEqual(STATE_MAX_IDS_PER_FIELD)
  })
  it('rejects oversized / non-string ids', () => {
    const longId = 'x'.repeat(500)
    const state = payloadToState({
      read: [longId, 'ok', 42 as unknown as string],
      flag: {},
      folder: {},
      deleted: [],
    })
    expect(state.reads.has('ok')).toBe(true)
    expect(state.reads.has(longId)).toBe(false)
  })
})

describe('F-DET-01: deterministic serialization', () => {
  it('emits ids in sorted order', () => {
    let s = createMailboxState()
    s = moveToFolder(s, 'mzzz', 'inbox')
    s = moveToFolder(s, 'maaa', 'archive')
    s.reads.add('r2')
    s.reads.add('r1')
    const payload = stateToPayload(s)
    expect(payload.read).toEqual(['r1', 'r2'])
    expect(Object.keys(payload.folder)).toEqual(['maaa', 'mzzz'])
  })
})
