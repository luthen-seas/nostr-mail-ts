// ─── NOSTR Mail Protocol — NIP-05 Resolution & Relay Discovery ──────────────
// Resolves NIP-05 identifiers, npub/hex pubkeys, and fetches inbox relays.

import { nip19 } from 'nostr-tools'
import type { SimplePool } from 'nostr-tools'

/** Default timeout for NIP-05 HTTP requests (in milliseconds). */
const NIP05_TIMEOUT_MS = 5000

/** Default timeout for relay queries (in milliseconds). */
const RELAY_QUERY_TIMEOUT_MS = 8000

/**
 * Resolve a NIP-05 address (user@domain) to a pubkey.
 * Fetches https://domain/.well-known/nostr.json?name=user
 * Returns the hex pubkey and optional relays, or null if not found.
 *
 * @param address - A NIP-05 identifier in the form user@domain.
 * @returns Resolved pubkey and optional relay list, or null on failure.
 */
export async function resolveNip05(address: string): Promise<{
  pubkey: string
  relays?: string[]
} | null> {
  // Parse user@domain
  const atIndex = address.indexOf('@')
  if (atIndex < 1 || atIndex === address.length - 1) {
    return null
  }

  const name = address.slice(0, atIndex).toLowerCase()
  const domain = address.slice(atIndex + 1).toLowerCase()

  // Validate domain (basic check — no slashes, at least one dot)
  if (domain.includes('/') || !domain.includes('.')) {
    return null
  }

  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), NIP05_TIMEOUT_MS)

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      // NIP-05 spec: clients SHOULD NOT send cookies or auth headers
    })

    if (!response.ok) {
      return null
    }

    const json = await response.json() as {
      names?: Record<string, string>
      relays?: Record<string, string[]>
    }

    // Extract pubkey from names object
    if (!json.names || typeof json.names !== 'object') {
      return null
    }

    const pubkey = json.names[name]
    if (!pubkey || typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkey)) {
      return null
    }

    const hexPubkey = pubkey.toLowerCase()

    // Extract relays if available
    let relays: string[] | undefined
    if (json.relays && typeof json.relays === 'object') {
      const pubkeyRelays = json.relays[hexPubkey]
      if (Array.isArray(pubkeyRelays) && pubkeyRelays.length > 0) {
        relays = pubkeyRelays.filter(
          (r): r is string => typeof r === 'string' && r.startsWith('wss://'),
        )
        if (relays.length === 0) relays = undefined
      }
    }

    return { pubkey: hexPubkey, relays }
  } catch {
    // Network errors, aborted requests, invalid JSON — all return null
    return null
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Resolve a recipient identifier to a pubkey.
 * Accepts: NIP-05 (user@domain), npub (bech32), hex pubkey.
 *
 * @param identifier - An npub1..., hex pubkey, or user@domain string.
 * @returns Resolved pubkey and optional relay list, or null if unrecognizable.
 */
export async function resolveRecipient(identifier: string): Promise<{
  pubkey: string
  relays?: string[]
} | null> {
  const trimmed = identifier.trim()

  // npub bech32 → decode to hex
  if (trimmed.startsWith('npub1')) {
    try {
      const decoded = nip19.decode(trimmed)
      if (decoded.type === 'npub') {
        return { pubkey: decoded.data }
      }
      // nprofile also works — includes relays
      if (decoded.type === 'nprofile') {
        return {
          pubkey: decoded.data.pubkey,
          relays: decoded.data.relays?.length ? decoded.data.relays : undefined,
        }
      }
      return null
    } catch {
      return null
    }
  }

  // nprofile bech32 → decode to hex + relays
  if (trimmed.startsWith('nprofile1')) {
    try {
      const decoded = nip19.decode(trimmed)
      if (decoded.type === 'nprofile') {
        return {
          pubkey: decoded.data.pubkey,
          relays: decoded.data.relays?.length ? decoded.data.relays : undefined,
        }
      }
      return null
    } catch {
      return null
    }
  }

  // 64 hex characters → return as-is
  if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    return { pubkey: trimmed.toLowerCase() }
  }

  // Contains '@' → treat as NIP-05
  if (trimmed.includes('@')) {
    return resolveNip05(trimmed)
  }

  return null
}

/**
 * Fetch a user's inbox relays from their kind 10050 event (NIP-17 DM relays).
 * Falls back to kind 10002 read relays (NIP-65) if 10050 not found.
 *
 * Kind 10050 tags: `["relay", "wss://relay.example.com"]`
 * Kind 10002 tags: `["r", "wss://relay.example.com"]` or
 *                  `["r", "wss://relay.example.com", "read"]`
 *
 * @param pubkey - Hex public key of the user whose inbox relays to fetch.
 * @param pool - A nostr-tools SimplePool instance for querying relays.
 * @param searchRelays - Relay URLs to query for the relay list events.
 * @returns Array of inbox relay URLs (may be empty if none found).
 */
export async function fetchInboxRelays(
  pubkey: string,
  pool: SimplePool,
  searchRelays: string[],
): Promise<string[]> {
  if (searchRelays.length === 0) {
    return []
  }

  // ── Try kind 10050 first (NIP-17 preferred inbox relays) ──────────────
  const inboxRelays = await queryRelayList(pool, pubkey, 10050, searchRelays)
  if (inboxRelays.length > 0) {
    return inboxRelays
  }

  // ── Fall back to kind 10002 read relays (NIP-65 relay list) ───────────
  const readRelays = await queryRelayList(pool, pubkey, 10002, searchRelays)
  return readRelays
}

/**
 * Query for a relay list event (kind 10050 or 10002) and extract relay URLs.
 */
async function queryRelayList(
  pool: SimplePool,
  pubkey: string,
  kind: number,
  searchRelays: string[],
): Promise<string[]> {
  return new Promise<string[]>((resolve) => {
    const timeout = setTimeout(() => {
      resolve([])
    }, RELAY_QUERY_TIMEOUT_MS)

    // querySync is not available; use subscribeManyEose for one-shot queries
    const events: Array<{ created_at: number; tags: string[][] }> = []

    const sub = pool.subscribeManyEose(
      searchRelays,
      [{ kinds: [kind], authors: [pubkey], limit: 1 }],
      {
        onevent(event) {
          events.push(event)
        },
        onclose() {
          clearTimeout(timeout)

          if (events.length === 0) {
            resolve([])
            return
          }

          // Pick the most recent event
          const latest = events.reduce((a, b) =>
            a.created_at >= b.created_at ? a : b,
          )

          const relays = extractRelayUrls(latest.tags, kind)
          resolve(relays)
        },
      },
    )

    // Safety: ensure we don't hang forever even if onclose never fires
    setTimeout(() => {
      try { sub.close() } catch { /* ignore */ }
    }, RELAY_QUERY_TIMEOUT_MS + 500)
  })
}

/**
 * Extract relay URLs from event tags based on kind conventions.
 *
 * Kind 10050 uses `["relay", url]` tags.
 * Kind 10002 uses `["r", url]` or `["r", url, "read"]` tags.
 * For 10002, we only want read relays (unmarked or explicitly "read").
 */
function extractRelayUrls(tags: string[][], kind: number): string[] {
  const relays: string[] = []

  if (kind === 10050) {
    // NIP-17: ["relay", "wss://..."]
    for (const tag of tags) {
      if (tag[0] === 'relay' && tag[1] && isValidRelayUrl(tag[1])) {
        relays.push(tag[1])
      }
    }
  } else if (kind === 10002) {
    // NIP-65: ["r", "wss://...", optional_marker]
    // Include if no marker or marker is "read"
    for (const tag of tags) {
      if (tag[0] === 'r' && tag[1] && isValidRelayUrl(tag[1])) {
        const marker = tag[2]
        if (!marker || marker === 'read') {
          relays.push(tag[1])
        }
      }
    }
  }

  return relays
}

/**
 * Basic validation for relay URLs (must be wss:// or ws://).
 */
function isValidRelayUrl(url: string): boolean {
  return url.startsWith('wss://') || url.startsWith('ws://')
}
