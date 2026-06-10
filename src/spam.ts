// ─── NOSTR Mail Protocol — Anti-Spam Tier Evaluation ────────────────────────
// Implements the 3-tier trust model: contacts -> Cashu P2PK -> quarantine/reject.

import { verifyPostageStructure } from './cashu.js'
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
 *   the minimum amount and (when `recipientPubkey` is supplied) is
 *   structurally locked to the recipient. Delivered to inbox.
 * - **Tier 2**: None of the above. Quarantined or rejected per policy.
 *
 * Per AMEND-006 the structural P2PK check (`verifyPostageStructure`) runs
 * synchronously here. The async mint swap (`verifyPostage`) is the caller's
 * responsibility once the message is admitted to the inbox.
 *
 * @param senderPubkey - The sender's hex public key (from the seal).
 * @param contactList - Set of pubkeys the recipient follows (kind 3).
 * @param cashuPostage - Cashu postage token from the rumor, if present.
 * @param policy - The recipient's spam policy (kind 10097).
 * @param recipientPubkey - The receiver's hex pubkey, used to verify P2PK
 *   lock target. When omitted, structural validation is skipped — callers
 *   building unit tests against synthetic vectors may pass `undefined`,
 *   but production receive paths MUST supply it.
 * @returns The tier classification with reason and recommended action.
 */
export function evaluateSpamTier(
  senderPubkey: string,
  contactList: Set<string>,
  cashuPostage: CashuPostage | undefined,
  policy: SpamPolicy,
  recipientPubkey?: string,
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
  // F-SPAM-01: the authoritative amount and mint come from the DECODED,
  // P2PK-verified token — never from the advisory cashu-amount / cashu-mint
  // tags, which are attacker-controlled and sit outside the token.
  if (cashuPostage) {
    if (!recipientPubkey) {
      // Without the recipient pubkey we cannot verify the P2PK lock target,
      // so postage can never qualify for Tier 1 (production receive paths
      // MUST supply recipientPubkey).
      return {
        tier: 2,
        reason: 'Cashu postage present but recipient pubkey unavailable for P2PK verification',
        action: policy.unknownAction,
      }
    }

    const result = verifyPostageStructure(cashuPostage, recipientPubkey)
    if (!result.ok) {
      return {
        tier: 2,
        reason: `Cashu structural validation failed: ${result.error}`,
        action: policy.unknownAction,
      }
    }

    // Verified token value, not the advisory tag.
    if (result.amount < policy.cashuMinSats) {
      return {
        tier: 2,
        reason: `Cashu postage ${result.amount} sats below minimum ${policy.cashuMinSats} sats (verified token value)`,
        action: policy.unknownAction,
      }
    }

    // Allowlist checked against the VERIFIED mint, not the tag.
    if (policy.acceptedMints.length > 0 && !policy.acceptedMints.includes(result.mint)) {
      return {
        tier: 2,
        reason: `Cashu mint ${result.mint} is not in accepted mints list`,
        action: policy.unknownAction,
      }
    }

    return {
      tier: 1,
      reason: `Valid Cashu P2PK postage: ${result.amount} sats`,
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
      case 'cashu-min-sats': {
        // F-SPAM-02: NaN/negative would poison the `amount < min` comparison
        // (x < NaN is always false → the floor would be disabled). Clamp.
        const parsed = parseInt(value ?? '', 10)
        policy.cashuMinSats = Number.isFinite(parsed) && parsed >= 0 ? parsed : DEFAULT_SPAM_POLICY.cashuMinSats
        break
      }
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
