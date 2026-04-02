// ─── NOSTR Mail Protocol — Thread Reconstruction ────────────────────────────
// Builds conversation trees from parsed mail messages using reply/thread tags.

import type { ParsedMail, ThreadNode } from './types.js'

/**
 * Build a thread tree from a set of mail messages.
 *
 * Messages reference their parent via the `replyTo` field (from the `reply`
 * tag) and the conversation root via the `threadId` field (from the `thread`
 * tag). This function reconstructs the tree structure.
 *
 * Messages whose parent is not in the provided set, or that have no
 * `replyTo`, become root nodes. Children are sorted by `createdAt`.
 *
 * @param messages - Array of parsed mail messages (from any folder/thread).
 * @returns Array of root ThreadNode trees.
 */
export function buildThread(messages: ParsedMail[]): ThreadNode[] {
  if (messages.length === 0) return []

  // Step 1: Create a node for each message, indexed by ID
  const nodeMap = new Map<string, ThreadNode>()
  for (const msg of messages) {
    nodeMap.set(msg.id, {
      message: msg,
      children: [],
      parent: undefined,
    })
  }

  // Step 2: Link children to parents via replyTo
  const roots: ThreadNode[] = []

  for (const msg of messages) {
    const node = nodeMap.get(msg.id)
    if (!node) continue

    if (msg.replyTo) {
      const parentNode = nodeMap.get(msg.replyTo)
      if (parentNode) {
        // Parent is in our message set — link them
        node.parent = parentNode
        parentNode.children.push(node)
        continue
      }
    }

    // No replyTo, or parent not in the set — this is a root
    roots.push(node)
  }

  // Step 3: Sort children at every level by createdAt (ascending)
  const sortChildren = (node: ThreadNode): void => {
    node.children.sort((a, b) => a.message.createdAt - b.message.createdAt)
    for (const child of node.children) {
      sortChildren(child)
    }
  }

  for (const root of roots) {
    sortChildren(root)
  }

  // Sort roots by createdAt as well
  roots.sort((a, b) => a.message.createdAt - b.message.createdAt)

  return roots
}

/**
 * Flatten a thread tree into chronological order using DFS traversal.
 *
 * Within each level, messages are ordered by `createdAt`. The traversal
 * visits the parent first, then recurses into children — producing a
 * natural conversation flow.
 *
 * @param roots - Array of root ThreadNode trees (from buildThread).
 * @returns Flat array of ParsedMail in conversation order.
 */
export function flattenThread(roots: ThreadNode[]): ParsedMail[] {
  const result: ParsedMail[] = []

  const visit = (node: ThreadNode): void => {
    result.push(node.message)
    for (const child of node.children) {
      visit(child)
    }
  }

  // Roots are already sorted by buildThread
  for (const root of roots) {
    visit(root)
  }

  return result
}

/**
 * Group messages by thread ID (conversation clustering).
 *
 * Messages with a `threadId` are grouped under that ID. Messages without
 * a `threadId` that are not referenced as a parent by any other message
 * form their own single-message thread (keyed by their own ID).
 *
 * @param messages - Array of parsed mail messages.
 * @returns Map from thread root ID to the messages in that thread.
 */
export function groupByThread(messages: ParsedMail[]): Map<string, ParsedMail[]> {
  const threads = new Map<string, ParsedMail[]>()

  // Collect all known thread IDs and all replyTo targets
  const replyTargets = new Set<string>()
  for (const msg of messages) {
    if (msg.replyTo) {
      replyTargets.add(msg.replyTo)
    }
  }

  for (const msg of messages) {
    // Determine the thread key:
    // 1. If the message has an explicit threadId, use it
    // 2. Otherwise, use the message's own ID (it starts a new thread)
    const threadKey = msg.threadId ?? msg.id

    const existing = threads.get(threadKey)
    if (existing) {
      existing.push(msg)
    } else {
      threads.set(threadKey, [msg])
    }
  }

  // Sort each thread's messages by createdAt
  for (const [, msgs] of threads) {
    msgs.sort((a, b) => a.createdAt - b.createdAt)
  }

  return threads
}

/**
 * Find the latest message in each thread (for inbox summary display).
 *
 * @param threads - Map from thread ID to messages (from groupByThread).
 * @returns Array of the most recent message per thread, sorted newest first.
 */
export function threadSummaries(threads: Map<string, ParsedMail[]>): ParsedMail[] {
  const summaries: ParsedMail[] = []

  for (const [, msgs] of threads) {
    if (msgs.length > 0) {
      // Last message in the sorted array is the most recent
      summaries.push(msgs[msgs.length - 1]!)
    }
  }

  // Sort by most recent first
  summaries.sort((a, b) => b.createdAt - a.createdAt)

  return summaries
}
