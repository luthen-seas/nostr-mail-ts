import { describe, it, expect } from 'vitest'
import { evaluateSpamTier, DEFAULT_SPAM_POLICY, createSpamPolicy } from '../src/spam.js'
import type { SpamPolicy, CashuPostage } from '../src/types.js'

const SENDER_PUBKEY = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

describe('evaluateSpamTier', () => {
  it('Tier 0: contact list sender', () => {
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, undefined, DEFAULT_SPAM_POLICY)

    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('contact')
  })

  it('Tier 1: valid Cashu P2PK token above threshold', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, DEFAULT_SPAM_POLICY)

    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('21')
  })

  it('Cashu amount below threshold -> Tier 2 (quarantine)', () => {
    const policy = createSpamPolicy({ cashuMinSats: 21 })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 5,
      p2pk: true,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, policy)

    expect(result.tier).toBe(2)
    expect(result.reason).toContain('below')
  })

  it('No Cashu, not contact -> Tier 2', () => {
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, undefined, DEFAULT_SPAM_POLICY)

    expect(result.tier).toBe(2)
    expect(result.action).toBe('quarantine')
    expect(result.reason).toContain('No qualifying signal')
  })

  it('non-P2PK Cashu token -> Tier 2 (rejected)', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: false,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, DEFAULT_SPAM_POLICY)

    expect(result.tier).toBe(2)
    expect(result.reason).toContain('P2PK')
  })

  it('Cashu mint not in accepted list -> Tier 2', () => {
    const policy = createSpamPolicy({
      acceptedMints: ['https://trusted-mint.example.com'],
    })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://untrusted-mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, policy)

    expect(result.tier).toBe(2)
    expect(result.reason).toContain('not in accepted')
  })

  it('Cashu from accepted mint passes -> Tier 1', () => {
    const policy = createSpamPolicy({
      acceptedMints: ['https://trusted-mint.example.com'],
    })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://trusted-mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, policy)

    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
  })

  it('Contact + Cashu -> Tier 0 (contact takes precedence)', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, DEFAULT_SPAM_POLICY)

    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
  })

  it('Tier 2: action is reject when policy says reject', () => {
    const policy = createSpamPolicy({ unknownAction: 'reject' })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, undefined, policy)

    expect(result.tier).toBe(2)
    expect(result.action).toBe('reject')
  })

  it('respects contactsFree=false policy', () => {
    const policy = createSpamPolicy({ contactsFree: false })
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, undefined, policy)

    // Contact check disabled, falls through to tier 2
    expect(result.tier).toBe(2)
  })

  it('custom cashuMinSats threshold', () => {
    const policy = createSpamPolicy({ cashuMinSats: 100 })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 50,
      p2pk: true,
    }
    const contacts = new Set<string>()

    const result = evaluateSpamTier(SENDER_PUBKEY, contacts, cashu, policy)

    expect(result.tier).toBe(2)
  })
})
