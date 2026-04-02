import { describe, it, expect } from 'vitest'
import * as nip44 from 'nostr-tools/nip44'
import { hexToBytes, bytesToHex } from 'nostr-tools/utils'
import { readFileSync } from 'fs'

const vectors = JSON.parse(readFileSync('/tmp/nip44-vectors.json', 'utf-8'))

describe('NIP-44 official test vector compatibility', () => {
  describe('conversation key derivation', () => {
    const cases = vectors.v2?.valid?.get_conversation_key ?? []
    for (let i = 0; i < cases.length; i++) {
      const v = cases[i]
      it(`vector ${i}: derive conversation key`, () => {
        const sk = hexToBytes(v.sec1)
        const pk = v.pub2
        const expected = v.conversation_key
        const actual = bytesToHex(nip44.v2.utils.getConversationKey(sk, pk))
        expect(actual).toBe(expected)
      })
    }
  })

  describe('encrypt/decrypt round-trip', () => {
    const cases = vectors.v2?.valid?.encrypt_decrypt ?? []
    for (let i = 0; i < Math.min(cases.length, 20); i++) {
      const v = cases[i]
      it(`vector ${i}: encrypt then decrypt recovers plaintext`, () => {
        const convKey = hexToBytes(v.conversation_key)
        const plaintext = v.plaintext
        const encrypted = nip44.v2.encrypt(plaintext, convKey)
        const decrypted = nip44.v2.decrypt(encrypted, convKey)
        expect(decrypted).toBe(plaintext)
      })
    }
  })

  describe('invalid ciphertexts must throw', () => {
    const cases = vectors.v2?.invalid?.decrypt ?? []
    for (let i = 0; i < cases.length; i++) {
      const v = cases[i]
      it(`vector ${i}: ${v.note ?? 'invalid ciphertext'}`, () => {
        const convKey = hexToBytes(v.conversation_key)
        expect(() => nip44.v2.decrypt(v.ciphertext, convKey)).toThrow()
      })
    }
  })
})
