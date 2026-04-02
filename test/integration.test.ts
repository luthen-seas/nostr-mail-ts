import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { createMailRumor, parseMailRumor } from '../src/mail.js'
import { wrapMail } from '../src/wrap.js'
import { unwrapMail } from '../src/unwrap.js'
import { buildThread, flattenThread } from '../src/thread.js'
import { evaluateSpamTier, DEFAULT_SPAM_POLICY } from '../src/spam.js'
import {
  createMailboxState,
  markRead,
  isRead,
  toggleFlag,
  getFlags,
  moveToFolder,
  getFolder,
  stateToTags,
  tagsToState,
} from '../src/state.js'
import type { ParsedMail } from '../src/types.js'

describe('end-to-end: send and receive mail', () => {
  // Generate real keypairs
  const ALICE_PRIVKEY = generateSecretKey()
  const ALICE_PUBKEY = getPublicKey(ALICE_PRIVKEY)
  const BOB_PRIVKEY = generateSecretKey()
  const BOB_PUBKEY = getPublicKey(BOB_PRIVKEY)
  const CHARLIE_PRIVKEY = generateSecretKey()
  const CHARLIE_PUBKEY = getPublicKey(CHARLIE_PRIVKEY)

  it('Alice sends to Bob, Bob decrypts and reads', async () => {
    // 1. Alice creates mail rumor
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Meeting tomorrow',
      body: 'Hey Bob, can we meet at 3pm tomorrow?',
      createdAt: 1711843200,
    })

    expect(rumor.kind).toBe(1400)

    // 2. Alice wraps for Bob
    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    expect(wrapEvent.kind).toBe(1059)
    expect(wrapEvent.tags).toContainEqual(['p', BOB_PUBKEY])

    // 3. Bob unwraps
    const unwrapped = await unwrapMail(wrapEvent, BOB_PRIVKEY)
    expect(unwrapped.verified).toBe(true)
    expect(unwrapped.senderPubkey).toBe(ALICE_PUBKEY)

    // 4. Bob parses rumor
    const parsed = parseMailRumor(unwrapped.rumor)

    // 5. Verify: subject, body, sender, recipient match
    expect(parsed.from).toBe(ALICE_PUBKEY)
    expect(parsed.subject).toBe('Meeting tomorrow')
    expect(parsed.body).toBe('Hey Bob, can we meet at 3pm tomorrow?')
    expect(parsed.to).toHaveLength(1)
    expect(parsed.to[0]!.pubkey).toBe(BOB_PUBKEY)

    // 6. Bob evaluates spam tier (Alice in contacts -> Tier 0)
    //    evaluateSpamTier expects a ParsedMail (full type from types.ts)
    const fullParsedMail: ParsedMail = {
      id: wrapEvent.id,
      from: { pubkey: ALICE_PUBKEY },
      to: [{ pubkey: BOB_PUBKEY }],
      cc: [],
      subject: parsed.subject,
      body: parsed.body,
      contentType: 'text/plain',
      attachments: [],
      createdAt: rumor.created_at,
      receivedAt: Math.floor(Date.now() / 1000),
    }

    const contacts = new Set([ALICE_PUBKEY])
    const tier = evaluateSpamTier(fullParsedMail, DEFAULT_SPAM_POLICY, contacts, false, 0)
    expect(tier.tier).toBe(0)
    expect(tier.action).toBe('inbox')

    // 7. Bob marks as read
    let mailboxState = createMailboxState()
    mailboxState = markRead(mailboxState, wrapEvent.id)

    // 8. Verify read state is persistent (survives serialization round-trip)
    const tags = stateToTags(mailboxState)
    const restored = tagsToState(tags)
    expect(isRead(restored, wrapEvent.id)).toBe(true)
  })

  it('Alice sends to Bob and Charlie (CC), both decrypt', async () => {
    // 1. Alice creates rumor with Bob (TO) and Charlie (CC)
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [
        { pubkey: BOB_PUBKEY, role: 'to' },
        { pubkey: CHARLIE_PUBKEY, role: 'cc' },
      ],
      subject: 'Project update',
      body: 'Both of you should see this.',
      createdAt: 1711843200,
    })

    // 2. Alice wraps separately for each recipient
    const wrapForBob = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const wrapForCharlie = await wrapMail(rumor, ALICE_PRIVKEY, CHARLIE_PUBKEY)

    // Wraps are different events
    expect(wrapForBob.id).not.toBe(wrapForCharlie.id)
    expect(wrapForBob.pubkey).not.toBe(wrapForCharlie.pubkey)

    // 3. Bob decrypts his copy
    const bobResult = await unwrapMail(wrapForBob, BOB_PRIVKEY)
    expect(bobResult.verified).toBe(true)
    expect(bobResult.senderPubkey).toBe(ALICE_PUBKEY)
    expect(bobResult.rumor.content).toBe('Both of you should see this.')

    // 4. Charlie decrypts his copy
    const charlieResult = await unwrapMail(wrapForCharlie, CHARLIE_PRIVKEY)
    expect(charlieResult.verified).toBe(true)
    expect(charlieResult.senderPubkey).toBe(ALICE_PUBKEY)
    expect(charlieResult.rumor.content).toBe('Both of you should see this.')

    // 5. Both parse the rumor and see the same content
    const bobParsed = parseMailRumor(bobResult.rumor)
    const charlieParsed = parseMailRumor(charlieResult.rumor)

    expect(bobParsed.subject).toBe(charlieParsed.subject)
    expect(bobParsed.body).toBe(charlieParsed.body)
    expect(bobParsed.to).toHaveLength(2) // Bob (to) + Charlie (cc)
    expect(bobParsed.to.some(r => r.pubkey === BOB_PUBKEY)).toBe(true)

    // 6. Cross-decryption fails
    await expect(unwrapMail(wrapForCharlie, BOB_PRIVKEY)).rejects.toThrow()
    await expect(unwrapMail(wrapForBob, CHARLIE_PRIVKEY)).rejects.toThrow()
  })

  it('Bob replies to Alice, thread is reconstructed', async () => {
    // 1. Alice sends original message
    const originalRumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Dinner plans',
      body: 'Want to grab dinner Friday?',
      createdAt: 1711843200,
    })

    const originalWrap = await wrapMail(originalRumor, ALICE_PRIVKEY, BOB_PUBKEY)
    const originalUnwrapped = await unwrapMail(originalWrap, BOB_PRIVKEY)
    const originalParsed = parseMailRumor(originalUnwrapped.rumor)
    const originalId = originalWrap.id

    // 2. Bob replies (with reply + thread tags)
    const replyRumor = createMailRumor({
      senderPubkey: BOB_PUBKEY,
      recipients: [{ pubkey: ALICE_PUBKEY, role: 'to' }],
      subject: 'Re: Dinner plans',
      body: 'Sure, how about 7pm?',
      replyTo: originalId,
      threadId: originalId,
      createdAt: 1711846800,
    })

    const replyWrap = await wrapMail(replyRumor, BOB_PRIVKEY, ALICE_PUBKEY)
    const replyUnwrapped = await unwrapMail(replyWrap, ALICE_PRIVKEY)
    const replyParsed = parseMailRumor(replyUnwrapped.rumor)

    // Verify reply references
    expect(replyParsed.replyTo).toBe(originalId)
    expect(replyParsed.threadId).toBe(originalId)

    // 3. Build thread tree from both messages
    const originalMail: ParsedMail = {
      id: originalId,
      from: { pubkey: ALICE_PUBKEY },
      to: [{ pubkey: BOB_PUBKEY }],
      cc: [],
      subject: originalParsed.subject,
      body: originalParsed.body,
      contentType: 'text/plain',
      attachments: [],
      createdAt: 1711843200,
      receivedAt: 1711843200,
    }

    const replyMail: ParsedMail = {
      id: replyWrap.id,
      from: { pubkey: BOB_PUBKEY },
      to: [{ pubkey: ALICE_PUBKEY }],
      cc: [],
      subject: replyParsed.subject,
      body: replyParsed.body,
      contentType: 'text/plain',
      attachments: [],
      replyTo: originalId,
      threadId: originalId,
      createdAt: 1711846800,
      receivedAt: 1711846800,
    }

    const roots = buildThread([originalMail, replyMail])

    // 4. Verify: root = Alice's message, child = Bob's reply
    expect(roots).toHaveLength(1)
    expect(roots[0]!.message.id).toBe(originalId)
    expect(roots[0]!.message.subject).toBe('Dinner plans')
    expect(roots[0]!.children).toHaveLength(1)
    expect(roots[0]!.children[0]!.message.id).toBe(replyWrap.id)
    expect(roots[0]!.children[0]!.message.subject).toBe('Re: Dinner plans')

    // Flatten should give chronological order
    const flat = flattenThread(roots)
    expect(flat).toHaveLength(2)
    expect(flat[0]!.id).toBe(originalId)
    expect(flat[1]!.id).toBe(replyWrap.id)
  })

  it('full workflow: create, encrypt, decrypt, evaluate spam, manage state', async () => {
    // 1. Alice sends a paid message to unknown Bob (not in contacts)
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Business inquiry',
      body: 'I would like to discuss a partnership.',
      cashuPostage: {
        token: 'cashuAeyJwcm9vZnMiOltdLCJtaW50IjoiaHR0cHM6Ly9taW50LmV4YW1wbGUuY29tIn0=',
        mint: 'https://mint.example.com',
        amount: 42,
        p2pk: true,
      },
      createdAt: 1711843200,
    })

    // 2. Wrap and send
    const wrapEvent = await wrapMail(rumor, ALICE_PRIVKEY, BOB_PUBKEY)

    // 3. Bob receives and decrypts
    const unwrapped = await unwrapMail(wrapEvent, BOB_PRIVKEY)
    const parsed = parseMailRumor(unwrapped.rumor)

    expect(parsed.subject).toBe('Business inquiry')
    expect(parsed.cashuPostage).toBeDefined()
    expect(parsed.cashuPostage!.amount).toBe(42)

    // 4. Evaluate spam -- Alice is unknown but paid with Cashu
    const fullMail: ParsedMail = {
      id: wrapEvent.id,
      from: { pubkey: ALICE_PUBKEY },
      to: [{ pubkey: BOB_PUBKEY }],
      cc: [],
      subject: parsed.subject,
      body: parsed.body,
      contentType: 'text/plain',
      attachments: [],
      cashuPostage: parsed.cashuPostage,
      createdAt: rumor.created_at,
      receivedAt: Math.floor(Date.now() / 1000),
    }

    const contacts = new Set<string>() // Alice is NOT a contact
    const tier = evaluateSpamTier(fullMail, DEFAULT_SPAM_POLICY, contacts, false, 0)
    expect(tier.tier).toBe(3) // Cashu tier
    expect(tier.action).toBe('inbox')

    // 5. Bob reads the message and stars it
    let state = createMailboxState()
    state = markRead(state, wrapEvent.id)
    state = toggleFlag(state, wrapEvent.id, 'starred')
    state = moveToFolder(state, wrapEvent.id, 'inbox')

    expect(isRead(state, wrapEvent.id)).toBe(true)
    expect(getFlags(state, wrapEvent.id)).toContain('starred')
    expect(getFolder(state, wrapEvent.id)).toBe('inbox')

    // 6. State survives serialization
    const tags = stateToTags(state)
    const restored = tagsToState(tags)

    expect(isRead(restored, wrapEvent.id)).toBe(true)
    expect(getFlags(restored, wrapEvent.id)).toContain('starred')
    expect(getFolder(restored, wrapEvent.id)).toBe('inbox')
  })
})
