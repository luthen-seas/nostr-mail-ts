import { describe, it, expect } from 'vitest'
import { evaluateSpamTier, DEFAULT_SPAM_POLICY, createSpamPolicy } from '../src/spam.js'
import { createMailRumor, parseMailRumor } from '../src/mail.js'
import type { SpamPolicy, ParsedMail, CashuPostage } from '../src/types.js'

/**
 * Helper to build a minimal ParsedMail for spam tier tests.
 * parseMailRumor returns a ParsedMailRumor (from mail.ts), but evaluateSpamTier
 * takes the full ParsedMail (from types.ts). We construct a compatible object.
 */
function makeParsedMail(
  senderPubkey: string,
  opts?: { cashuPostage?: CashuPostage }
): ParsedMail {
  return {
    id: 'test-wrap-id',
    from: { pubkey: senderPubkey },
    to: [{ pubkey: 'recipient-pubkey' }],
    cc: [],
    subject: 'Test',
    body: 'Test body',
    contentType: 'text/plain',
    attachments: [],
    cashuPostage: opts?.cashuPostage,
    createdAt: 1711843200,
    receivedAt: 1711843200,
  }
}

const SENDER_PUBKEY = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

describe('evaluateSpamTier', () => {
  it('Tier 0: contact list sender', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('contact')
  })

  it('Tier 1: NIP-05 verified sender', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, true, 0)

    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('NIP-05')
  })

  it('Tier 2: sufficient PoW', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 24)

    expect(result.tier).toBe(2)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('24')
  })

  it('Tier 2: exactly minimum PoW passes', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 20)

    expect(result.tier).toBe(2)
    expect(result.action).toBe('inbox')
  })

  it('insufficient PoW (just below minimum) falls through to Tier 5', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 19)

    expect(result.tier).toBe(5)
  })

  it('Tier 3: valid Cashu P2PK token', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(3)
    expect(result.action).toBe('inbox')
    expect(result.reason).toContain('21')
  })

  it('Tier 3: Cashu amount above minimum passes', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 100,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(3)
    expect(result.action).toBe('inbox')
  })

  it('Cashu amount below minimum is rejected', () => {
    const policy = createSpamPolicy({ cashuMinSats: 21 })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 5, // below 21
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    expect(result.tier).toBe(5)
    expect(result.reason).toContain('below')
  })

  it('non-P2PK Cashu token is rejected', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: false,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(5)
    expect(result.reason).toContain('P2PK')
  })

  it('Cashu mint not in accepted list is rejected', () => {
    const policy = createSpamPolicy({
      acceptedMints: ['https://trusted-mint.example.com'],
    })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://untrusted-mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    expect(result.tier).toBe(5)
    expect(result.reason).toContain('not in accepted')
  })

  it('Cashu from accepted mint passes', () => {
    const policy = createSpamPolicy({
      acceptedMints: ['https://trusted-mint.example.com'],
    })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://trusted-mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    expect(result.tier).toBe(3)
    expect(result.action).toBe('inbox')
  })

  it('Tier 5: unknown sender, nothing qualifying -> quarantine', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(5)
    expect(result.action).toBe('quarantine')
    expect(result.reason).toContain('No trust signals')
  })

  it('Tier 5: action is reject when policy says reject', () => {
    const policy = createSpamPolicy({ unknownAction: 'reject' })
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    expect(result.tier).toBe(5)
    expect(result.action).toBe('reject')
  })

  it('contact with Cashu token gets Tier 0 (contact takes precedence)', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, false, 0)

    expect(result.tier).toBe(0)
    expect(result.action).toBe('inbox')
  })

  it('NIP-05 + PoW gets Tier 1 (NIP-05 wins as higher free tier)', () => {
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, true, 24)

    expect(result.tier).toBe(1)
    expect(result.action).toBe('inbox')
  })

  it('contact + NIP-05 + PoW + Cashu still gets Tier 0', () => {
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 100,
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(mail, DEFAULT_SPAM_POLICY, contacts, true, 24)

    expect(result.tier).toBe(0)
  })

  it('respects contactsFree=false policy', () => {
    const policy = createSpamPolicy({ contactsFree: false })
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set([SENDER_PUBKEY])

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    // Contact check disabled, falls through to tier 5
    expect(result.tier).toBe(5)
  })

  it('respects nip05Free=false policy', () => {
    const policy = createSpamPolicy({ nip05Free: false })
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, true, 0)

    // NIP-05 check disabled, falls through to tier 5
    expect(result.tier).toBe(5)
  })

  it('custom powMinBits threshold', () => {
    const policy = createSpamPolicy({ powMinBits: 32 })
    const mail = makeParsedMail(SENDER_PUBKEY)
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 24)

    // 24 bits < 32 bits required
    expect(result.tier).toBe(5)
  })

  it('custom cashuMinSats threshold', () => {
    const policy = createSpamPolicy({ cashuMinSats: 100 })
    const cashu: CashuPostage = {
      token: 'cashuAtoken',
      mint: 'https://mint.example.com',
      amount: 50, // below 100
      p2pk: true,
    }
    const mail = makeParsedMail(SENDER_PUBKEY, { cashuPostage: cashu })
    const contacts = new Set<string>()

    const result = evaluateSpamTier(mail, policy, contacts, false, 0)

    expect(result.tier).toBe(5)
  })
})
