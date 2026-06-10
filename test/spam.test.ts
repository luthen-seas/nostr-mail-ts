import { describe, it, expect } from 'vitest'
import { evaluateSpamTier, DEFAULT_SPAM_POLICY, createSpamPolicy, parsePolicyTags } from '../src/spam.js'
import type { CashuPostage } from '../src/types.js'
import { p2pkPostage, bearerTokenString, p2pkTokenString } from './helpers/cashu-token.js'

const SENDER_PUBKEY = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'
// Recipient that postage is locked to; passed to evaluateSpamTier as the 5th arg.
const RECIPIENT_PUBKEY = '98b30d5bfd1e2e751d7a57e7a58e67e15b3f2e0a90f9f7e8e40f7f6e5d4c3b2a'

describe('evaluateSpamTier', () => {
  it('Tier 0: contact list sender', () => {
    const contacts = new Set([SENDER_PUBKEY])
    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, undefined, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('contact')
  })

  it('Tier 1: valid Cashu P2PK token above threshold', () => {
    const cashu = p2pkPostage({ mint: 'https://mint.example.com', verified: [21], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('21')
  })

  // F-SPAM-01 regression: a real 1-sat token whose advisory tag claims 100000
  // must NOT qualify — admission is gated on the verified token value.
  it('forged cashu-amount tag does not qualify for Tier 1', () => {
    const cashu = p2pkPostage({
      mint: 'https://mint.example.com',
      verified: [1],
      lockXonly: RECIPIENT_PUBKEY,
      claimAmount: 100000,
    })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.reason).toContain('verified token value')
  })

  // F-SPAM-02(c): allowlist checked against the verified token mint, not the tag.
  it('forged cashu-mint tag does not bypass the accepted-mint allowlist', () => {
    const policy = createSpamPolicy({ acceptedMints: ['https://trusted-mint.example.com'] })
    const cashu = p2pkPostage({
      mint: 'https://evil-mint.example.com',
      verified: [21],
      lockXonly: RECIPIENT_PUBKEY,
      claimMint: 'https://trusted-mint.example.com',
    })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.reason).toContain('not in accepted')
  })

  it('Cashu amount below threshold -> Tier 2', () => {
    const policy = createSpamPolicy({ cashuMinSats: 21 })
    const cashu = p2pkPostage({ mint: 'https://mint.example.com', verified: [5], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.reason).toContain('below')
  })

  it('No Cashu, not contact -> Tier 2', () => {
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), undefined, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.action).toBe('quarantine')
    expect(result.reason).toContain('No qualifying signal')
  })

  it('non-P2PK (bearer) Cashu token -> Tier 2', () => {
    const cashu: CashuPostage = {
      token: bearerTokenString('https://mint.example.com', [21]),
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: false,
    }
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
  })

  it('P2PK token locked to a different pubkey -> Tier 2', () => {
    const cashu: CashuPostage = {
      token: p2pkTokenString('https://mint.example.com', [21], SENDER_PUBKEY), // locked to sender, not recipient
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
  })

  it('Cashu mint not in accepted list -> Tier 2', () => {
    const policy = createSpamPolicy({ acceptedMints: ['https://trusted-mint.example.com'] })
    const cashu = p2pkPostage({ mint: 'https://untrusted-mint.example.com', verified: [21], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.reason).toContain('not in accepted')
  })

  it('Cashu from accepted mint passes -> Tier 1', () => {
    const policy = createSpamPolicy({ acceptedMints: ['https://trusted-mint.example.com'] })
    const cashu = p2pkPostage({ mint: 'https://trusted-mint.example.com', verified: [21], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
  })

  it('Contact + Cashu -> Tier 0 (contact takes precedence)', () => {
    const cashu = p2pkPostage({ mint: 'https://mint.example.com', verified: [21], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set([SENDER_PUBKEY]), cashu, DEFAULT_SPAM_POLICY, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
  })

  it('postage without recipientPubkey cannot reach Tier 1', () => {
    const cashu = p2pkPostage({ mint: 'https://mint.example.com', verified: [21], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, DEFAULT_SPAM_POLICY)
    expect(result.tier).toBe(2)
  })

  it('Tier 2: action is reject when policy says reject', () => {
    const policy = createSpamPolicy({ unknownAction: 'reject' })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), undefined, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
    expect(result.action).toBe('reject')
  })

  it('respects contactsFree=false policy', () => {
    const policy = createSpamPolicy({ contactsFree: false })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set([SENDER_PUBKEY]), undefined, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
  })

  it('custom cashuMinSats threshold', () => {
    const policy = createSpamPolicy({ cashuMinSats: 100 })
    const cashu = p2pkPostage({ mint: 'https://mint.example.com', verified: [50], lockXonly: RECIPIENT_PUBKEY })
    const result = evaluateSpamTier(SENDER_PUBKEY, new Set(), cashu, policy, RECIPIENT_PUBKEY)
    expect(result.tier).toBe(2)
  })
})

describe('parsePolicyTags — NaN safety (F-SPAM-02)', () => {
  it('falls back to default min-sats on a non-numeric cashu-min-sats tag', () => {
    const policy = parsePolicyTags([['cashu-min-sats', 'not-a-number']])
    expect(policy.cashuMinSats).toBe(DEFAULT_SPAM_POLICY.cashuMinSats)
  })
  it('rejects negative min-sats', () => {
    const policy = parsePolicyTags([['cashu-min-sats', '-5']])
    expect(policy.cashuMinSats).toBe(DEFAULT_SPAM_POLICY.cashuMinSats)
  })
  it('accepts a valid min-sats', () => {
    const policy = parsePolicyTags([['cashu-min-sats', '42']])
    expect(policy.cashuMinSats).toBe(42)
  })
})
