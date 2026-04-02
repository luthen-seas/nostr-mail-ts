// ─── NOSTR Mail Protocol — Relay Communication Helpers ──────────────────────
// Publishes gift-wrapped events and subscribes to inbox streams via SimplePool.

import type { SimplePool, VerifiedEvent } from 'nostr-tools'
import type { SubCloser } from 'nostr-tools/pool'

/** Default timeout for relay publish operations (in milliseconds). */
const PUBLISH_TIMEOUT_MS = 10000

/** Result of publishing an event to multiple relays. */
export interface PublishResult {
  /** Relay URLs that accepted the event. */
  accepted: string[]
  /** Relay URLs that rejected or timed out. */
  rejected: string[]
}

/**
 * Publish a gift-wrapped event to a set of relays.
 * Returns the list of relays that accepted the event and those that rejected.
 *
 * Uses SimplePool.publish() which sends to all relays in parallel.
 * Each relay independently accepts or rejects the event.
 *
 * @param pool - A nostr-tools SimplePool instance.
 * @param event - A signed event (typically kind 1059 gift wrap).
 * @param relays - Relay URLs to publish to.
 * @param timeoutMs - Per-relay timeout in milliseconds (default: 10000).
 * @returns Lists of accepted and rejected relay URLs.
 */
export async function publishToRelays(
  pool: SimplePool,
  event: VerifiedEvent,
  relays: string[],
  timeoutMs: number = PUBLISH_TIMEOUT_MS,
): Promise<PublishResult> {
  if (relays.length === 0) {
    return { accepted: [], rejected: [] }
  }

  const accepted: string[] = []
  const rejected: string[] = []

  // Publish to each relay individually to track per-relay results
  const promises = relays.map(async (relay) => {
    try {
      const result = await Promise.race([
        publishToSingleRelay(pool, event, relay),
        timeout(timeoutMs),
      ])

      if (result === 'timeout') {
        rejected.push(relay)
      } else {
        accepted.push(relay)
      }
    } catch {
      rejected.push(relay)
    }
  })

  await Promise.allSettled(promises)

  return { accepted, rejected }
}

/**
 * Publish an event to a single relay via the pool.
 */
async function publishToSingleRelay(
  pool: SimplePool,
  event: VerifiedEvent,
  relay: string,
): Promise<void> {
  // SimplePool.publish returns Promise<void>[] (one per relay)
  const results = pool.publish([relay], event)
  // Wait for the single relay's result
  await results[0]
}

/**
 * Create a timeout promise that resolves to 'timeout' after the given ms.
 */
function timeout(ms: number): Promise<'timeout'> {
  return new Promise((resolve) => setTimeout(() => resolve('timeout'), ms))
}

/** An event received from an inbox subscription. */
export interface InboxEvent {
  /** The raw kind 1059 gift wrap event. */
  event: {
    id: string
    pubkey: string
    created_at: number
    kind: number
    tags: string[][]
    content: string
    sig: string
  }
  /** The relay URL this event was received from. */
  relay?: string
}

/**
 * Subscribe to inbox events (kind 1059) for a pubkey.
 * Returns an async iterable of received events with a close() method.
 *
 * Filter: `{"#p": [pubkey], "kinds": [1059], "since": since}`
 *
 * Events are deduplicated by event ID (relays may send the same gift wrap
 * from multiple sources). The `since` parameter enables efficient
 * reconnection — pass the timestamp of the last processed event.
 *
 * @param pool - A nostr-tools SimplePool instance.
 * @param pubkey - Our hex public key (to receive events tagged to us).
 * @param relays - Relay URLs to subscribe to (typically our inbox relays).
 * @param since - Unix timestamp to start from (default: now).
 * @returns An async iterable that yields inbox events, with a close() method.
 */
export function subscribeInbox(
  pool: SimplePool,
  pubkey: string,
  relays: string[],
  since?: number,
): AsyncIterable<InboxEvent> & { close: () => void } {
  const seenIds = new Set<string>()

  // Buffer for events received before the consumer starts iterating
  const buffer: InboxEvent[] = []

  // Resolve function for the current pending next() call
  let pendingResolve: ((value: IteratorResult<InboxEvent>) => void) | null = null

  // Whether the subscription has been closed
  let closed = false

  // Track the subscription closer
  let subCloser: SubCloser | undefined

  // Set up the relay subscription
  const filter = {
    '#p': [pubkey],
    kinds: [1059],
    ...(since !== undefined ? { since } : {}),
  }

  try {
    subCloser = pool.subscribeMany(relays, filter, {
      onevent(event) {
        // Deduplicate by event ID
        if (seenIds.has(event.id)) return
        seenIds.add(event.id)

        const inboxEvent: InboxEvent = { event }

        // If there's a pending next() call, resolve it immediately
        if (pendingResolve) {
          const resolve = pendingResolve
          pendingResolve = null
          resolve({ value: inboxEvent, done: false })
        } else {
          // Otherwise buffer the event
          buffer.push(inboxEvent)
        }
      },
    })
  } catch {
    closed = true
  }

  function close(): void {
    if (closed) return
    closed = true

    // Close the relay subscription
    if (subCloser) {
      try { subCloser.close() } catch { /* ignore */ }
    }

    // Resolve any pending next() call with done
    if (pendingResolve) {
      const resolve = pendingResolve
      pendingResolve = null
      resolve({ value: undefined as unknown as InboxEvent, done: true })
    }
  }

  const asyncIterator: AsyncIterator<InboxEvent> = {
    next(): Promise<IteratorResult<InboxEvent>> {
      // If there are buffered events, return the next one immediately
      if (buffer.length > 0) {
        return Promise.resolve({
          value: buffer.shift()!,
          done: false,
        })
      }

      // If closed, signal completion
      if (closed) {
        return Promise.resolve({
          value: undefined as unknown as InboxEvent,
          done: true,
        })
      }

      // Wait for the next event
      return new Promise((resolve) => {
        pendingResolve = resolve
      })
    },

    return(): Promise<IteratorResult<InboxEvent>> {
      close()
      return Promise.resolve({
        value: undefined as unknown as InboxEvent,
        done: true,
      })
    },
  }

  return {
    [Symbol.asyncIterator]() {
      return asyncIterator
    },
    close,
  }
}

/**
 * Fetch existing inbox events in a one-shot query (EOSE-based).
 * Useful for initial sync — fetches all matching events until End-Of-Stored-Events.
 *
 * @param pool - A nostr-tools SimplePool instance.
 * @param pubkey - Our hex public key.
 * @param relays - Relay URLs to query.
 * @param since - Fetch events created after this Unix timestamp.
 * @param limit - Maximum number of events to fetch (default: 500).
 * @returns Array of inbox events, deduplicated by ID.
 */
export async function fetchInboxEvents(
  pool: SimplePool,
  pubkey: string,
  relays: string[],
  since?: number,
  limit: number = 500,
): Promise<InboxEvent[]> {
  if (relays.length === 0) {
    return []
  }

  const seenIds = new Set<string>()
  const events: InboxEvent[] = []

  const filter = {
    '#p': [pubkey],
    kinds: [1059],
    ...(since !== undefined ? { since } : {}),
    limit,
  }

  return new Promise<InboxEvent[]>((resolve) => {
    const timeoutId = setTimeout(() => {
      try { sub.close() } catch { /* ignore */ }
      resolve(events)
    }, 15000) // 15s safety timeout

    const sub = pool.subscribeManyEose(relays, filter, {
      onevent(event) {
        if (seenIds.has(event.id)) return
        seenIds.add(event.id)
        events.push({ event })
      },
      onclose() {
        clearTimeout(timeoutId)
        resolve(events)
      },
    })
  })
}
