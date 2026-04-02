import { describe, it, expect } from 'vitest'
import { wrapMail } from '../src/wrap.js'
import { unwrapMail } from '../src/unwrap.js'
import { createMailRumor } from '../src/mail.js'
import { generateSecretKey, getPublicKey } from 'nostr-tools'

describe('wrapMail + unwrapMail round-trip', () => {
  // Generate real keypairs for Alice, Bob, Charlie
  const ALICE_PRIVKEY = generateSecretKey()
  const ALICE_PUBKEY = getPublicKey(ALICE_PRIVKEY)
  const BOB_PRIVKEY = generateSecretKey()
  const BOB_PUBKEY = getPublicKey(BOB_PRIVKEY)
  const CHARLIE_PRIVKEY = generateSecretKey()
  const CHARLIE_PUBKEY = getPublicKey(CHARLIE_PRIVKEY)

  it('encrypts and decrypts a simple message', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Test',
      body: 'Hello Bob!',
      createdAt: 1711843200,
    })

    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)

    // Verify wrap structure
    expect(wrapEvent.kind).toBe(1059)
    expect(wrapEvent.pubkey).not.toBe(ALICE_PUBKEY) // ephemeral key, not sender
    expect(wrapEvent.tags).toContainEqual(['p', BOB_PUBKEY])
    expect(wrapEvent.sig).toBeDefined()
    expect(typeof wrapEvent.sig).toBe('string')
    expect(wrapEvent.sig.length).toBe(128) // schnorr sig is 64 bytes = 128 hex chars
    expect(wrapEvent.id).toBeDefined()

    // Decrypt
    const result = await unwrapMail(wrapEvent, BOB_PRIVKEY)
    expect(result.senderPubkey).toBe(ALICE_PUBKEY)
    expect(result.verified).toBe(true)
    expect(result.rumor.content).toBe('Hello Bob!')
    expect(result.rumor.kind).toBe(1111)
    expect(result.rumor.pubkey).toBe(ALICE_PUBKEY)
  })

  it('produces different ciphertext for same message (random nonce)', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Nonce test',
      body: 'Same content, different ciphertext.',
      createdAt: 1711843200,
    })

    const wrap1 = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const wrap2 = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)

    // Different ciphertext due to NIP-44 random nonce
    expect(wrap1.content).not.toBe(wrap2.content)

    // Both should decrypt to the same content
    const result1 = await unwrapMail(wrap1, BOB_PRIVKEY)
    const result2 = await unwrapMail(wrap2, BOB_PRIVKEY)
    expect(result1.rumor.content).toBe(result2.rumor.content)
    expect(result1.rumor.content).toBe('Same content, different ciphertext.')
  })

  it('uses different ephemeral keys per wrap', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Ephemeral test',
      body: 'Different ephemeral keys expected.',
      createdAt: 1711843200,
    })

    const wrap1 = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const wrap2 = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)

    // Different ephemeral pubkeys on the outer wrap
    expect(wrap1.pubkey).not.toBe(wrap2.pubkey)
    // Neither should be the sender's real pubkey
    expect(wrap1.pubkey).not.toBe(ALICE_PUBKEY)
    expect(wrap2.pubkey).not.toBe(ALICE_PUBKEY)
  })

  it('randomizes seal and wrap timestamps', async () => {
    const baseTime = 1711843200

    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Timestamp test',
      body: 'Check timestamp randomization.',
      createdAt: baseTime,
    })

    // Collect multiple wraps to check timestamp variance
    const wraps = await Promise.all(
      Array.from({ length: 5 }, () => wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY))
    )

    // Wrap timestamps should be within +-2 days (172800 seconds) of now
    const now = Math.floor(Date.now() / 1000)
    const maxOffset = 172800

    for (const wrap of wraps) {
      const diff = Math.abs(wrap.created_at - now)
      expect(diff).toBeLessThanOrEqual(maxOffset + 5) // small tolerance for test execution time
    }

    // With 5 wraps, not all timestamps should be identical (probabilistic but near-certain)
    const uniqueTimestamps = new Set(wraps.map(w => w.created_at))
    expect(uniqueTimestamps.size).toBeGreaterThanOrEqual(2)
  })

  it('wrap cannot be decrypted by non-recipient', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Secret',
      body: 'Only for Bob.',
      createdAt: 1711843200,
    })

    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)

    // Charlie should not be able to decrypt
    await expect(unwrapMail(wrapEvent, CHARLIE_PRIVKEY)).rejects.toThrow()
  })

  it('sender identity is verified from seal signature', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Verification test',
      body: 'Verify the sender.',
      createdAt: 1711843200,
    })

    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const result = await unwrapMail(wrapEvent, BOB_PRIVKEY)

    // The sender pubkey should come from the seal, not from the rumor
    expect(result.senderPubkey).toBe(ALICE_PUBKEY)
    // The seal signature should be verified
    expect(result.verified).toBe(true)
    // The rumor's pubkey should match the seal's pubkey
    expect(result.rumor.pubkey).toBe(ALICE_PUBKEY)
  })

  it('self-copy can be decrypted by sender', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Self-copy',
      body: 'Saved to sent folder.',
      createdAt: 1711843200,
    })

    // Wrap for the sender (self-copy for sent folder)
    const selfWrap = await wrapMail(rumor, ALICE_PRIVKEY, ALICE_PUBKEY)

    // Sender should be able to decrypt their own self-copy
    expect(selfWrap.tags).toContainEqual(['p', ALICE_PUBKEY])

    const result = await unwrapMail(selfWrap, ALICE_PRIVKEY)
    expect(result.senderPubkey).toBe(ALICE_PUBKEY)
    expect(result.verified).toBe(true)
    expect(result.rumor.content).toBe('Saved to sent folder.')
    expect(result.rumor.kind).toBe(1111)
  })

  it('preserves all rumor fields through wrap/unwrap', async () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [
        { pubkey: BOB_PUBKEY, role: 'to' },
        { pubkey: CHARLIE_PUBKEY, role: 'cc' },
      ],
      subject: 'Full round-trip',
      body: 'Check all fields survive encryption.',
      contentType: 'text/markdown',
      replyTo: 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233',
      threadId: '11223344556677881122334455667788112233445566778811223344556677aa',
      createdAt: 1711843200,
    })

    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const result = await unwrapMail(wrapEvent, BOB_PRIVKEY)

    // All tags should survive the round-trip
    expect(result.rumor.tags).toEqual(rumor.tags)
    expect(result.rumor.content).toBe(rumor.content)
    expect(result.rumor.kind).toBe(rumor.kind)
    expect(result.rumor.pubkey).toBe(rumor.pubkey)
    expect(result.rumor.created_at).toBe(rumor.created_at)
  })

  it('rejects non-1059 events', async () => {
    const fakeEvent = {
      id: '0'.repeat(64),
      pubkey: ALICE_PUBKEY,
      content: 'not encrypted',
      kind: 1, // wrong kind
      created_at: 1711843200,
      tags: [],
      sig: '0'.repeat(128),
    }

    await expect(unwrapMail(fakeEvent, BOB_PRIVKEY)).rejects.toThrow('Expected kind 1059')
  })
})
