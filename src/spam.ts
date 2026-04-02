// ─── NOSTR Mail Protocol — Anti-Spam Tier Evaluation ────────────────────────
// Implements the 6-tier trust model: contacts -> NIP-05 -> PoW -> Cashu -> unknown.

import type { ParsedMail, SpamPolicy, SpamTier } from './types.js'

/** Default spam policy values. */
export const DEFAULT_SPAM_POLICY: SpamPolicy = {
  contactsFree: true,
  nip05Free: true,
  powMinBits: 20,
  cashuMinSats: 1,
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
 * - **Tier 1**: Sender has a valid NIP-05 identifier. Delivered to inbox
 *   if the policy allows NIP-05 senders.
 * - **Tier 2**: The gift wrap event has sufficient NIP-13 proof-of-work.
 *   Delivered to inbox if PoW meets the policy threshold.
 * - **Tier 3**: The message includes a valid Cashu P2PK token meeting
 *   the minimum amount. Delivered to inbox.
 * - **Tier 4**: Reserved for future trust signals.
 * - **Tier 5**: None of the above. Quarantined or rejected per policy.
 *
 * @param mail - The parsed mail message.
 * @param policy - The recipient's spam policy (kind 10097).
 * @param contactList - Set of pubkeys the recipient follows (kind 3).
 * @param nip05Verified - Whether the sender has a valid NIP-05.
 * @param eventPowBits - NIP-13 PoW difficulty bits on the wrap event.
 * @returns The tier classification with reason and recommended action.
 */
export function evaluateSpamTier(
  mail: ParsedMail,
  policy: SpamPolicy,
  contactList: Set<string>,
  nip05Verified: boolean,
  eventPowBits: number,
): SpamTier {
  // ── Tier 0: Sender is a contact ──────────────────────────────────────
  if (policy.contactsFree && contactList.has(mail.from.pubkey)) {
    return {
      tier: 0,
      reason: 'Sender is in contact list',
      action: 'inbox',
    }
  }

  // ── Tier 1: Sender has valid NIP-05 ──────────────────────────────────
  if (policy.nip05Free && nip05Verified) {
    return {
      tier: 1,
      reason: 'Sender has verified NIP-05 identity',
      action: 'inbox',
    }
  }

  // ── Tier 2: Sufficient proof-of-work ─────────────────────────────────
  if (policy.powMinBits > 0 && eventPowBits >= policy.powMinBits) {
    return {
      tier: 2,
      reason: `Event has ${eventPowBits} PoW bits (required: ${policy.powMinBits})`,
      action: 'inbox',
    }
  }

  // ── Tier 3: Valid Cashu P2PK postage ─────────────────────────────────
  if (mail.cashuPostage) {
    const { cashuPostage } = mail

    // Check P2PK requirement
    if (!cashuPostage.p2pk) {
      return {
        tier: 5,
        reason: 'Cashu token is not P2PK locked (P2PK is required)',
        action: policy.unknownAction,
      }
    }

    // Check minimum amount
    if (cashuPostage.amount < policy.cashuMinSats) {
      return {
        tier: 5,
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
        tier: 5,
        reason: `Cashu mint ${cashuPostage.mint} is not in accepted mints list`,
        action: policy.unknownAction,
      }
    }

    return {
      tier: 3,
      reason: `Valid Cashu P2PK postage: ${cashuPostage.amount} sats`,
      action: 'inbox',
    }
  }

  // ── Tier 5: Unknown sender, no trust signals ─────────────────────────
  return {
    tier: 5,
    reason: 'No trust signals: not a contact, no NIP-05, insufficient PoW, no Cashu postage',
    action: policy.unknownAction,
  }
}

/**
 * Parse a kind 10097 spam policy event's tags into a SpamPolicy.
 *
 * Expected tags:
 * - `["contacts-free", "true"|"false"]`
 * - `["nip05-free", "true"|"false"]`
 * - `["pow-min-bits", "20"]`
 * - `["cashu-min-sats", "1"]`
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
      case 'nip05-free':
        policy.nip05Free = value !== 'false'
        break
      case 'pow-min-bits':
        policy.powMinBits = parseInt(value ?? '0', 10)
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
    ['nip05-free', String(policy.nip05Free)],
    ['pow-min-bits', String(policy.powMinBits)],
    ['cashu-min-sats', String(policy.cashuMinSats)],
    ['unknown-action', policy.unknownAction],
  ]

  for (const mint of policy.acceptedMints) {
    tags.push(['accepted-mint', mint])
  }

  return tags
}
