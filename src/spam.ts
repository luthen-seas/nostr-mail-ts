// ─── NOSTR Mail Protocol — Anti-Spam Tier Evaluation ────────────────────────
// Implements the 3-tier trust model: contacts -> Cashu P2PK -> quarantine/reject.

import type { CashuPostage, SpamPolicy, SpamTier } from './types.js'

/** Default spam policy values. */
export const DEFAULT_SPAM_POLICY: SpamPolicy = {
  contactsFree: true,
  cashuMinSats: 10,
  acceptedMints: [],
  unknownAction: 'quarantine',
}

/**
 * Create a complete SpamPolicy by merging partial overrides with defaults.
 *
 * @param overrides - Partial policy values to override defaults.
 * @returns A complete SpamPolicy.
 */
export function createSpamPolicy(overrides?: Partial<SpamPolicy>): SpamPolicy {
  return { ...DEFAULT_SPAM_POLICY, ...overrides }
}

/**
 * Evaluate which anti-spam tier a received mail message falls into.
 *
 * The tier model (in priority order):
 * - **Tier 0**: Sender is in the recipient's contact list (kind 3 follows).
 *   Always delivered to inbox.
 * - **Tier 1**: The message includes a valid Cashu P2PK token meeting
 *   the minimum amount. Delivered to inbox.
 * - **Tier 2**: None of the above. Quarantined or rejected per policy.
 *
 * @param senderPubkey - The sender's hex public key (from the seal).
 * @param contactList - Set of pubkeys the recipient follows (kind 3).
 * @param cashuPostage - Cashu postage token from the rumor, if present.
 * @param policy - The recipient's spam policy (kind 10097).
 * @returns The tier classification with reason and recommended action.
 */
export function evaluateSpamTier(
  senderPubkey: string,
  contactList: Set<string>,
  cashuPostage: CashuPostage | undefined,
  policy: SpamPolicy,
): SpamTier {
  // ── Tier 0: Sender is a contact ──────────────────────────────────────
  if (policy.contactsFree && contactList.has(senderPubkey)) {
    return {
      tier: 0,
      reason: 'Sender is in contact list',
      action: 'inbox',
    }
  }

  // ── Tier 1: Valid Cashu P2PK postage ─────────────────────────────────
  if (cashuPostage) {
    // Check P2PK requirement
    if (!cashuPostage.p2pk) {
      return {
        tier: 2,
        reason: 'Cashu token is not P2PK locked (P2PK is required)',
        action: policy.unknownAction,
      }
    }

    // Check minimum amount
    if (cashuPostage.amount < policy.cashuMinSats) {
      return {
        tier: 2,
        reason: `Cashu postage ${cashuPostage.amount} sats below minimum ${policy.cashuMinSats} sats`,
        action: policy.unknownAction,
      }
    }

    // Check mint is accepted (if acceptedMints is non-empty)
    if (
      policy.acceptedMints.length > 0 &&
      !policy.acceptedMints.includes(cashuPostage.mint)
    ) {
      return {
        tier: 2,
        reason: `Cashu mint ${cashuPostage.mint} is not in accepted mints list`,
        action: policy.unknownAction,
      }
    }

    return {
      tier: 1,
      reason: `Valid Cashu P2PK postage: ${cashuPostage.amount} sats`,
      action: 'inbox',
    }
  }

  // ── Tier 2: Unknown sender, no qualifying signal ─────────────────────
  return {
    tier: 2,
    reason: 'No qualifying signal: not a contact, no valid Cashu postage',
    action: policy.unknownAction,
  }
}

/**
 * Parse a kind 10097 spam policy event's tags into a SpamPolicy.
 *
 * Expected tags:
 * - `["contacts-free", "true"|"false"]`
 * - `["cashu-min-sats", "10"]`
 * - `["accepted-mint", mintUrl]` (repeatable)
 * - `["unknown-action", "quarantine"|"reject"]`
 *
 * @param tags - Tags from a kind 10097 event.
 * @returns A complete SpamPolicy.
 */
export function parsePolicyTags(tags: string[][]): SpamPolicy {
  const policy: SpamPolicy = { ...DEFAULT_SPAM_POLICY, acceptedMints: [] }

  for (const tag of tags) {
    const key = tag[0]
    const value = tag[1]

    switch (key) {
      case 'contacts-free':
        policy.contactsFree = value !== 'false'
        break
      case 'cashu-min-sats':
        policy.cashuMinSats = parseInt(value ?? '0', 10)
        break
      case 'accepted-mint':
        if (value) {
          policy.acceptedMints.push(value)
        }
        break
      case 'unknown-action':
        if (value === 'quarantine' || value === 'reject') {
          policy.unknownAction = value
        }
        break
    }
  }

  return policy
}

/**
 * Serialize a SpamPolicy to kind 10097 event tags.
 *
 * @param policy - The spam policy to serialize.
 * @returns Tags array for a kind 10097 event.
 */
export function policyToTags(policy: SpamPolicy): string[][] {
  const tags: string[][] = [
    ['contacts-free', String(policy.contactsFree)],
    ['cashu-min-sats', String(policy.cashuMinSats)],
    ['unknown-action', policy.unknownAction],
  ]

  for (const mint of policy.acceptedMints) {
    tags.push(['accepted-mint', mint])
  }

  return tags
}
