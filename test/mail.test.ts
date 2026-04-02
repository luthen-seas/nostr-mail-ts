import { describe, it, expect } from 'vitest'
import { createMailRumor, parseMailRumor } from '../src/mail.js'
import type { MailAttachment, CashuPostage } from '../src/types.js'

describe('createMailRumor', () => {
  const ALICE_PUBKEY = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a6748'
  const BOB_PUBKEY = '98b30d5bfd1e2e751d7a57e7a58e67e15b3f2e0a90f9f7e8e40f7f6e5d4c3b2a'
  const CHARLIE_PUBKEY = 'd3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4'

  it('creates a simple text message', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Hello',
      body: 'Hi Bob, how are you?',
      createdAt: 1711843200,
    })

    expect(rumor.kind).toBe(1400)
    expect(rumor.pubkey).toBe(ALICE_PUBKEY)
    expect(rumor.content).toBe('Hi Bob, how are you?')
    expect(rumor.created_at).toBe(1711843200)
    expect(rumor.tags).toContainEqual(['p', BOB_PUBKEY, '', 'to'])
    expect(rumor.tags).toContainEqual(['subject', 'Hello'])
    // Rumor is unsigned — no id or sig fields on MailMessage
    expect(rumor).not.toHaveProperty('id')
    expect(rumor).not.toHaveProperty('sig')
  })

  it('creates a message with CC recipients', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [
        { pubkey: BOB_PUBKEY, role: 'to' },
        { pubkey: CHARLIE_PUBKEY, role: 'cc' },
      ],
      subject: 'Team Update',
      body: 'FYI for both of you.',
      createdAt: 1711843200,
    })

    expect(rumor.kind).toBe(1400)
    expect(rumor.tags).toContainEqual(['p', BOB_PUBKEY, '', 'to'])
    expect(rumor.tags).toContainEqual(['p', CHARLIE_PUBKEY, '', 'cc'])

    // Verify order: p tags come first
    const pTags = rumor.tags.filter(t => t[0] === 'p')
    expect(pTags).toHaveLength(2)
    expect(pTags[0]![3]).toBe('to')
    expect(pTags[1]![3]).toBe('cc')
  })

  it('creates a reply with thread tags', () => {
    const ORIGINAL_ID = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'
    const ROOT_ID = '11223344556677881122334455667788112233445566778811223344556677aa'

    const rumor = createMailRumor({
      senderPubkey: BOB_PUBKEY,
      recipients: [{ pubkey: ALICE_PUBKEY, role: 'to' }],
      subject: 'Re: Hello',
      body: 'I am doing well, thanks!',
      replyTo: ORIGINAL_ID,
      threadId: ROOT_ID,
      createdAt: 1711846800,
    })

    expect(rumor.kind).toBe(1400)
    expect(rumor.tags).toContainEqual(['reply', ORIGINAL_ID, ''])
    expect(rumor.tags).toContainEqual(['thread', ROOT_ID, ''])
    expect(rumor.tags).toContainEqual(['subject', 'Re: Hello'])
  })

  it('creates a reply with relay hints on thread tags', () => {
    const ORIGINAL_ID = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'

    const rumor = createMailRumor({
      senderPubkey: BOB_PUBKEY,
      recipients: [{ pubkey: ALICE_PUBKEY, role: 'to' }],
      subject: 'Re: Hello',
      body: 'Reply with relay hint',
      replyTo: ORIGINAL_ID,
      replyToRelay: 'wss://relay.example.com',
      createdAt: 1711846800,
    })

    expect(rumor.tags).toContainEqual(['reply', ORIGINAL_ID, 'wss://relay.example.com'])
  })

  it('creates a message with attachments', () => {
    const attachment: MailAttachment = {
      hash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abc1',
      filename: 'report.pdf',
      mimeType: 'application/pdf',
      size: 102400,
      encryptionKey: 'deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567',
      blossomUrls: ['https://blossom.example.com', 'https://blossom2.example.com'],
    }

    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Report attached',
      body: 'Please see the attached report.',
      attachments: [attachment],
      createdAt: 1711843200,
    })

    // Attachment tag
    expect(rumor.tags).toContainEqual([
      'attachment',
      attachment.hash,
      'report.pdf',
      'application/pdf',
      '102400',
    ])

    // Encryption key tag
    expect(rumor.tags).toContainEqual([
      'attachment-key',
      attachment.hash,
      attachment.encryptionKey!,
    ])

    // Blossom URLs are deduplicated into a single tag
    const blossomTag = rumor.tags.find(t => t[0] === 'blossom')
    expect(blossomTag).toBeDefined()
    expect(blossomTag).toContain('https://blossom.example.com')
    expect(blossomTag).toContain('https://blossom2.example.com')
  })

  it('creates a message with Cashu postage', () => {
    const cashu: CashuPostage = {
      token: 'cashuAeyJwcm9vZnMiOlt7InByb29mcyI6W10sIm1pbnQiOiJodHRwczovL21pbnQuZXhhbXBsZS5jb20ifV19',
      mint: 'https://mint.example.com',
      amount: 21,
      p2pk: true,
    }

    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Paid message',
      body: 'This message includes postage.',
      cashuPostage: cashu,
      createdAt: 1711843200,
    })

    expect(rumor.tags).toContainEqual(['cashu', cashu.token])
    expect(rumor.tags).toContainEqual(['cashu-mint', 'https://mint.example.com'])
    expect(rumor.tags).toContainEqual(['cashu-amount', '21'])
  })

  it('creates a message with markdown content type', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Formatted',
      body: '# Hello\n\nThis is **bold**.',
      contentType: 'text/markdown',
      createdAt: 1711843200,
    })

    expect(rumor.tags).toContainEqual(['content-type', 'text/markdown'])
  })

  it('does not include content-type tag for text/plain (default)', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Plain text',
      body: 'Just regular text.',
      createdAt: 1711843200,
    })

    const contentTypeTags = rumor.tags.filter(t => t[0] === 'content-type')
    expect(contentTypeTags).toHaveLength(0)
  })

  it('does not include content-type tag when contentType is explicitly text/plain', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Plain text',
      body: 'Explicitly plain.',
      contentType: 'text/plain',
      createdAt: 1711843200,
    })

    const contentTypeTags = rumor.tags.filter(t => t[0] === 'content-type')
    expect(contentTypeTags).toHaveLength(0)
  })

  it('uses current time when createdAt is not specified', () => {
    const before = Math.floor(Date.now() / 1000)

    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'No timestamp',
      body: 'Auto-timestamp test.',
    })

    const after = Math.floor(Date.now() / 1000)
    expect(rumor.created_at).toBeGreaterThanOrEqual(before)
    expect(rumor.created_at).toBeLessThanOrEqual(after)
  })

  it('includes relay hint on recipient tag when provided', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, relay: 'wss://inbox.bob.com', role: 'to' }],
      subject: 'Relay hint',
      body: 'Test relay hint.',
      createdAt: 1711843200,
    })

    expect(rumor.tags).toContainEqual(['p', BOB_PUBKEY, 'wss://inbox.bob.com', 'to'])
  })
})

describe('parseMailRumor', () => {
  const ALICE_PUBKEY = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a6748'
  const BOB_PUBKEY = '98b30d5bfd1e2e751d7a57e7a58e67e15b3f2e0a90f9f7e8e40f7f6e5d4c3b2a'
  const CHARLIE_PUBKEY = 'd3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4'

  it('round-trips a simple message', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [{ pubkey: BOB_PUBKEY, role: 'to' }],
      subject: 'Hello',
      body: 'Hi Bob!',
      createdAt: 1711843200,
    })

    const parsed = parseMailRumor(rumor)

    expect(parsed.from).toBe(ALICE_PUBKEY)
    expect(parsed.subject).toBe('Hello')
    expect(parsed.body).toBe('Hi Bob!')
    expect(parsed.contentType).toBe('text/plain')
    expect(parsed.to.length).toBeGreaterThanOrEqual(1)
    expect(parsed.to.some(r => r.pubkey === BOB_PUBKEY)).toBe(true)
    expect(parsed.attachments).toHaveLength(0)
    expect(parsed.cashuPostage).toBeUndefined()
    expect(parsed.replyTo).toBeUndefined()
    expect(parsed.threadId).toBeUndefined()
  })

  it('round-trips a complex message with all fields', () => {
    const ORIGINAL_ID = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233'
    const ROOT_ID = '11223344556677881122334455667788112233445566778811223344556677aa'

    const attachment: MailAttachment = {
      hash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abc1',
      filename: 'photo.jpg',
      mimeType: 'image/jpeg',
      size: 204800,
      encryptionKey: 'deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567',
      blossomUrls: ['https://blossom.example.com'],
    }

    const cashu: CashuPostage = {
      token: 'cashuAtoken123',
      mint: 'https://mint.example.com',
      amount: 42,
      p2pk: true,
    }

    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [
        { pubkey: BOB_PUBKEY, role: 'to' },
        { pubkey: CHARLIE_PUBKEY, role: 'cc' },
      ],
      subject: 'Full-featured message',
      body: '# Rich content\n\nWith **markdown**.',
      contentType: 'text/markdown',
      attachments: [attachment],
      cashuPostage: cashu,
      replyTo: ORIGINAL_ID,
      threadId: ROOT_ID,
      createdAt: 1711843200,
    })

    const parsed = parseMailRumor(rumor)

    expect(parsed.from).toBe(ALICE_PUBKEY)
    expect(parsed.subject).toBe('Full-featured message')
    expect(parsed.body).toBe('# Rich content\n\nWith **markdown**.')
    expect(parsed.contentType).toBe('text/markdown')

    // Recipients (parseMailRumor returns all recipients in .to array with roles)
    expect(parsed.to).toHaveLength(2)
    expect(parsed.to.some(r => r.pubkey === BOB_PUBKEY && r.role === 'to')).toBe(true)
    expect(parsed.to.some(r => r.pubkey === CHARLIE_PUBKEY && r.role === 'cc')).toBe(true)

    // Attachments
    expect(parsed.attachments).toHaveLength(1)
    expect(parsed.attachments[0]!.hash).toBe(attachment.hash)
    expect(parsed.attachments[0]!.filename).toBe('photo.jpg')
    expect(parsed.attachments[0]!.mimeType).toBe('image/jpeg')
    expect(parsed.attachments[0]!.size).toBe(204800)
    expect(parsed.attachments[0]!.encryptionKey).toBe(attachment.encryptionKey)

    // Cashu postage
    expect(parsed.cashuPostage).toBeDefined()
    expect(parsed.cashuPostage!.token).toBe('cashuAtoken123')
    expect(parsed.cashuPostage!.mint).toBe('https://mint.example.com')
    expect(parsed.cashuPostage!.amount).toBe(42)
    expect(parsed.cashuPostage!.p2pk).toBe(true)

    // Threading
    expect(parsed.replyTo).toBe(ORIGINAL_ID)
    expect(parsed.threadId).toBe(ROOT_ID)
  })

  it('handles missing optional fields gracefully', () => {
    // Minimal rumor with just pubkey, kind, content, and a subject tag
    const minimalRumor = {
      kind: 1400 as const,
      pubkey: ALICE_PUBKEY,
      created_at: 1711843200,
      tags: [['subject', 'Minimal']],
      content: 'Bare minimum.',
    }

    const parsed = parseMailRumor(minimalRumor)

    expect(parsed.from).toBe(ALICE_PUBKEY)
    expect(parsed.subject).toBe('Minimal')
    expect(parsed.body).toBe('Bare minimum.')
    expect(parsed.contentType).toBe('text/plain')
    expect(parsed.to).toHaveLength(0)
    expect(parsed.attachments).toHaveLength(0)
    expect(parsed.cashuPostage).toBeUndefined()
    expect(parsed.replyTo).toBeUndefined()
    expect(parsed.threadId).toBeUndefined()
  })

  it('parses a rumor with no tags at all', () => {
    const noTagRumor = {
      kind: 1400 as const,
      pubkey: ALICE_PUBKEY,
      created_at: 1711843200,
      tags: [] as string[][],
      content: 'No tags.',
    }

    const parsed = parseMailRumor(noTagRumor)

    expect(parsed.from).toBe(ALICE_PUBKEY)
    expect(parsed.subject).toBe('')
    expect(parsed.body).toBe('No tags.')
    expect(parsed.to).toHaveLength(0)
  })

  it('handles multiple TO recipients', () => {
    const rumor = createMailRumor({
      senderPubkey: ALICE_PUBKEY,
      recipients: [
        { pubkey: BOB_PUBKEY, role: 'to' },
        { pubkey: CHARLIE_PUBKEY, role: 'to' },
      ],
      subject: 'Group TO',
      body: 'Sent to both.',
      createdAt: 1711843200,
    })

    const parsed = parseMailRumor(rumor)
    expect(parsed.to).toHaveLength(2)
    expect(parsed.to.map(r => r.pubkey)).toContain(BOB_PUBKEY)
    expect(parsed.to.map(r => r.pubkey)).toContain(CHARLIE_PUBKEY)
  })
})
