// Regression tests for R6 threading fixes (F-THREAD-01/02).
import { describe, it, expect } from 'vitest'
import { buildThread, flattenThread } from '../src/thread.js'
import type { ParsedMail } from '../src/types.js'

function msg(id: string, opts: { replyTo?: string; threadId?: string; createdAt?: number } = {}): ParsedMail {
  return {
    id,
    messageId: id,
    from: { pubkey: 'x' },
    to: [],
    cc: [],
    subject: '',
    body: '',
    contentType: 'text/plain',
    attachments: [],
    threadId: opts.threadId,
    replyTo: opts.replyTo,
    createdAt: opts.createdAt ?? 1,
    receivedAt: opts.createdAt ?? 1,
  }
}

describe('F-THREAD-01: thread-tag fallback (TS↔Go parity)', () => {
  it('a message with thread tag but no reply attaches under the thread root', () => {
    const root = msg('root', { createdAt: 1 })
    const child = msg('c1', { threadId: 'root', createdAt: 2 }) // no replyTo
    const trees = buildThread([root, child])
    expect(trees).toHaveLength(1)
    expect(trees[0]!.message.id).toBe('root')
    expect(flattenThread(trees).map((m) => m.id)).toEqual(['root', 'c1'])
  })
})

describe('F-THREAD-02: cyclic/self-referential messages are surfaced, not dropped', () => {
  it('self-reply is surfaced as a root', () => {
    const flat = flattenThread(buildThread([msg('X', { replyTo: 'X' })]))
    expect(flat.map((m) => m.id)).toEqual(['X'])
  })
  it('a 2-cycle surfaces both messages exactly once (no crash, no loss)', () => {
    const flat = flattenThread(buildThread([msg('A', { replyTo: 'B' }), msg('B', { replyTo: 'A' })]))
    expect(flat.map((m) => m.id).sort()).toEqual(['A', 'B'])
  })
  it('keep-first on colliding message-id (no displacement)', () => {
    const trees = buildThread([msg('dup', { createdAt: 1 }), msg('dup', { createdAt: 2 })])
    expect(flattenThread(trees)).toHaveLength(1)
    expect(flattenThread(trees)[0]!.createdAt).toBe(1) // first kept
  })
})
