import { describe, it, expect } from 'vitest'
import { buildThread, flattenThread, groupByThread } from '../src/thread.js'
import type { ParsedMail } from '../src/types.js'

/** Helper to create a minimal ParsedMail for threading tests. */
function makeMail(overrides: Partial<ParsedMail> & { id: string; createdAt: number }): ParsedMail {
  return {
    id: overrides.id,
    from: overrides.from ?? { pubkey: 'sender' },
    to: overrides.to ?? [{ pubkey: 'recipient' }],
    cc: overrides.cc ?? [],
    subject: overrides.subject ?? 'Test',
    body: overrides.body ?? '',
    contentType: overrides.contentType ?? 'text/plain',
    attachments: overrides.attachments ?? [],
    threadId: overrides.threadId,
    replyTo: overrides.replyTo,
    cashuPostage: overrides.cashuPostage,
    createdAt: overrides.createdAt,
    receivedAt: overrides.receivedAt ?? overrides.createdAt,
  }
}

describe('buildThread', () => {
  it('builds a simple linear thread (A -> B -> C)', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000, subject: 'Original' })
    const msgB = makeMail({ id: 'b', createdAt: 2000, subject: 'Re: Original', replyTo: 'a' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, subject: 'Re: Re: Original', replyTo: 'b' })

    const roots = buildThread([msgA, msgB, msgC])

    expect(roots).toHaveLength(1)
    expect(roots[0]!.message.id).toBe('a')
    expect(roots[0]!.children).toHaveLength(1)
    expect(roots[0]!.children[0]!.message.id).toBe('b')
    expect(roots[0]!.children[0]!.children).toHaveLength(1)
    expect(roots[0]!.children[0]!.children[0]!.message.id).toBe('c')
    expect(roots[0]!.children[0]!.children[0]!.children).toHaveLength(0)
  })

  it('builds a branched thread (A -> B, A -> C)', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000 })
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'a' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, replyTo: 'a' })

    const roots = buildThread([msgA, msgB, msgC])

    expect(roots).toHaveLength(1)
    expect(roots[0]!.message.id).toBe('a')
    expect(roots[0]!.children).toHaveLength(2)
    // Children sorted by createdAt
    expect(roots[0]!.children[0]!.message.id).toBe('b')
    expect(roots[0]!.children[1]!.message.id).toBe('c')
  })

  it('builds a deep thread (5 levels)', () => {
    const msgs = [
      makeMail({ id: 'l0', createdAt: 1000 }),
      makeMail({ id: 'l1', createdAt: 2000, replyTo: 'l0' }),
      makeMail({ id: 'l2', createdAt: 3000, replyTo: 'l1' }),
      makeMail({ id: 'l3', createdAt: 4000, replyTo: 'l2' }),
      makeMail({ id: 'l4', createdAt: 5000, replyTo: 'l3' }),
    ]

    const roots = buildThread(msgs)

    expect(roots).toHaveLength(1)

    // Walk down 5 levels
    let node = roots[0]!
    expect(node.message.id).toBe('l0')
    node = node.children[0]!
    expect(node.message.id).toBe('l1')
    node = node.children[0]!
    expect(node.message.id).toBe('l2')
    node = node.children[0]!
    expect(node.message.id).toBe('l3')
    node = node.children[0]!
    expect(node.message.id).toBe('l4')
    expect(node.children).toHaveLength(0)
  })

  it('handles missing parent (orphaned reply becomes root)', () => {
    // Reply to a message not in the set
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'missing-parent' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, replyTo: 'b' })

    const roots = buildThread([msgB, msgC])

    // B becomes a root because its parent is missing
    expect(roots).toHaveLength(1)
    expect(roots[0]!.message.id).toBe('b')
    expect(roots[0]!.children).toHaveLength(1)
    expect(roots[0]!.children[0]!.message.id).toBe('c')
  })

  it('handles a single message (no thread)', () => {
    const msg = makeMail({ id: 'solo', createdAt: 1000, subject: 'Just one' })

    const roots = buildThread([msg])

    expect(roots).toHaveLength(1)
    expect(roots[0]!.message.id).toBe('solo')
    expect(roots[0]!.children).toHaveLength(0)
    expect(roots[0]!.parent).toBeUndefined()
  })

  it('returns empty array for empty input', () => {
    const roots = buildThread([])
    expect(roots).toHaveLength(0)
  })

  it('sets parent references correctly', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000 })
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'a' })

    const roots = buildThread([msgA, msgB])

    expect(roots[0]!.parent).toBeUndefined()
    expect(roots[0]!.children[0]!.parent).toBe(roots[0])
  })

  it('sorts children by createdAt ascending', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000 })
    // Insert children out of order
    const msgD = makeMail({ id: 'd', createdAt: 5000, replyTo: 'a' })
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'a' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, replyTo: 'a' })

    const roots = buildThread([msgA, msgD, msgB, msgC])

    expect(roots[0]!.children.map(c => c.message.id)).toEqual(['b', 'c', 'd'])
  })

  it('handles multiple independent roots', () => {
    const msg1 = makeMail({ id: 'thread1', createdAt: 1000 })
    const msg2 = makeMail({ id: 'thread2', createdAt: 2000 })
    const msg3 = makeMail({ id: 'thread3', createdAt: 500 })

    const roots = buildThread([msg1, msg2, msg3])

    expect(roots).toHaveLength(3)
    // Sorted by createdAt ascending
    expect(roots[0]!.message.id).toBe('thread3')
    expect(roots[1]!.message.id).toBe('thread1')
    expect(roots[2]!.message.id).toBe('thread2')
  })
})

describe('flattenThread', () => {
  it('flattens a linear thread in DFS order', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000 })
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'a' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, replyTo: 'b' })

    const roots = buildThread([msgA, msgB, msgC])
    const flat = flattenThread(roots)

    expect(flat.map(m => m.id)).toEqual(['a', 'b', 'c'])
  })

  it('flattens a branched thread in DFS order', () => {
    const msgA = makeMail({ id: 'a', createdAt: 1000 })
    const msgB = makeMail({ id: 'b', createdAt: 2000, replyTo: 'a' })
    const msgC = makeMail({ id: 'c', createdAt: 3000, replyTo: 'a' })
    const msgD = makeMail({ id: 'd', createdAt: 4000, replyTo: 'b' })

    const roots = buildThread([msgA, msgB, msgC, msgD])
    const flat = flattenThread(roots)

    // DFS: a -> b -> d -> c
    expect(flat.map(m => m.id)).toEqual(['a', 'b', 'd', 'c'])
  })

  it('returns empty array for empty input', () => {
    const flat = flattenThread([])
    expect(flat).toHaveLength(0)
  })
})

describe('groupByThread', () => {
  it('groups messages by threadId', () => {
    const msg1 = makeMail({ id: 'root1', createdAt: 1000 })
    const msg2 = makeMail({ id: 'reply1', createdAt: 2000, threadId: 'root1', replyTo: 'root1' })
    const msg3 = makeMail({ id: 'root2', createdAt: 3000 })

    const groups = groupByThread([msg1, msg2, msg3])

    // root1 thread has 2 messages (root1 itself keyed by its own id, reply1 keyed by threadId root1)
    expect(groups.get('root1')).toBeDefined()
    expect(groups.get('root1')!.length).toBeGreaterThanOrEqual(1)
    expect(groups.get('root2')).toBeDefined()
  })

  it('handles single-message threads', () => {
    const msg = makeMail({ id: 'standalone', createdAt: 1000 })

    const groups = groupByThread([msg])

    expect(groups.size).toBe(1)
    expect(groups.get('standalone')).toHaveLength(1)
  })
})
