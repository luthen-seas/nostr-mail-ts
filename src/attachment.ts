// ─── NOSTR Mail Protocol — Blossom Encrypted File Attachments ───────────────
// Encrypts, uploads, downloads, and decrypts file attachments via Blossom.
// Uses AES-256-GCM (Web Crypto API) for file encryption.
// Attachments are external Blossom references, not inline.
// Encryption keys MUST use CSPRNG.

import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils'
import type { MailAttachment, AttachmentInput } from './types.js'

/** AES-256-GCM IV length in bytes. */
const AES_IV_LENGTH = 12

/** Default timeout for Blossom HTTP operations (in milliseconds). */
const BLOSSOM_TIMEOUT_MS = 30000

/**
 * Encrypt file data with AES-256-GCM using the Web Crypto API.
 *
 * Format: [12-byte IV] [ciphertext + 16-byte GCM auth tag]
 * The IV is prepended to the ciphertext for self-contained decryption.
 *
 * @param data - Plaintext file data.
 * @param key - 32-byte symmetric key.
 * @returns Encrypted data with prepended IV.
 */
async function encryptAesGcm(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const iv = randomBytes(AES_IV_LENGTH)

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    data,
  )

  // Prepend IV to ciphertext: [IV (12 bytes)] [ciphertext + auth tag]
  const result = new Uint8Array(iv.length + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), iv.length)
  return result
}

/**
 * Decrypt AES-256-GCM encrypted data.
 *
 * Expects format: [12-byte IV] [ciphertext + 16-byte GCM auth tag]
 *
 * @param encrypted - Encrypted data with prepended IV.
 * @param key - 32-byte symmetric key.
 * @returns Decrypted plaintext data.
 * @throws If decryption fails (wrong key, tampered data, etc.).
 */
async function decryptAesGcm(encrypted: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (encrypted.length < AES_IV_LENGTH + 16) {
    throw new Error('Encrypted data too short (must contain IV + auth tag)')
  }

  const iv = encrypted.slice(0, AES_IV_LENGTH)
  const ciphertext = encrypted.slice(AES_IV_LENGTH)

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext,
  )

  return new Uint8Array(plaintext)
}

/**
 * Encrypt and prepare a file for upload to Blossom.
 * Returns the encrypted data, hash, and metadata for inclusion in mail tags.
 *
 * Attachments are external Blossom references, not inline.
 * Encryption keys MUST use CSPRNG (crypto.getRandomValues).
 *
 * @param input - The raw attachment input (filename, data, MIME type).
 * @param blossomUrls - Blossom server URLs where the file will be uploaded.
 * @returns The encrypted file data (for upload) and attachment metadata (for mail tags).
 */
export async function prepareAttachment(
  input: AttachmentInput,
  blossomUrls: string[],
): Promise<{
  encryptedData: Uint8Array
  attachment: MailAttachment
}> {
  if (input.data.length === 0) {
    throw new Error('Attachment data is empty')
  }
  if (blossomUrls.length === 0) {
    throw new Error('At least one Blossom URL is required')
  }

  // Step 1: Generate random 32-byte symmetric key (CSPRNG)
  const encryptionKey = randomBytes(32)

  // Step 2: Encrypt file data with AES-256-GCM
  const encryptedData = await encryptAesGcm(input.data, encryptionKey)

  // Step 3: Compute SHA-256 hash of encrypted data (this is the Blossom hash)
  // Blossom identifies files by the hash of what's stored, which is the
  // encrypted data — not the plaintext.
  const hash = bytesToHex(sha256(encryptedData))

  // Step 4: Create MailAttachment metadata
  const attachment: MailAttachment = {
    hash,
    filename: input.filename,
    mimeType: input.mimeType,
    size: input.data.length, // Original plaintext size
    encryptionKey: bytesToHex(encryptionKey),
    blossomUrls,
  }

  return { encryptedData, attachment }
}

/**
 * Upload encrypted attachment data to a Blossom server.
 * Returns the URL where the file can be retrieved.
 *
 * Blossom upload: PUT /upload with Content-Type: application/octet-stream
 * Response: { sha256: "...", url: "...", size: ..., type: "...", created: ... }
 *
 * @param encryptedData - The encrypted file bytes to upload.
 * @param blossomUrl - Base URL of the Blossom server (e.g., "https://blossom.example.com").
 * @param authEvent - Optional NIP-98 authorization event for authenticated uploads.
 * @returns The URL where the uploaded file can be retrieved.
 * @throws If the upload fails.
 */
export async function uploadToBlossom(
  encryptedData: Uint8Array,
  blossomUrl: string,
  authEvent?: { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string },
): Promise<string> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), BLOSSOM_TIMEOUT_MS)

  try {
    // Normalize base URL (strip trailing slash)
    const baseUrl = blossomUrl.replace(/\/+$/, '')
    const uploadUrl = `${baseUrl}/upload`

    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
    }

    // NIP-98 HTTP Auth: include the signed auth event in the Authorization header
    if (authEvent) {
      const authBase64 = btoa(JSON.stringify(authEvent))
      headers['Authorization'] = `Nostr ${authBase64}`
    }

    const response = await fetch(uploadUrl, {
      method: 'PUT',
      headers,
      body: encryptedData,
      signal: controller.signal,
    })

    if (!response.ok) {
      const body = await response.text().catch(() => '')
      throw new Error(
        `Blossom upload failed: HTTP ${response.status}${body ? ` — ${body}` : ''}`,
      )
    }

    const result = await response.json() as {
      sha256?: string
      url?: string
      size?: number
    }

    if (!result.url || typeof result.url !== 'string') {
      throw new Error('Blossom upload response missing url field')
    }

    return result.url
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Upload an attachment to multiple Blossom servers for redundancy.
 * Attempts all servers and returns the list of successful URLs.
 *
 * @param encryptedData - The encrypted file bytes to upload.
 * @param blossomUrls - Array of Blossom server base URLs.
 * @param authEvent - Optional NIP-98 authorization event.
 * @returns Array of URLs where the file was successfully uploaded.
 */
export async function uploadToMultipleBlossom(
  encryptedData: Uint8Array,
  blossomUrls: string[],
  authEvent?: { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string },
): Promise<string[]> {
  const results = await Promise.allSettled(
    blossomUrls.map((url) => uploadToBlossom(encryptedData, url, authEvent)),
  )

  const successUrls: string[] = []
  for (const result of results) {
    if (result.status === 'fulfilled') {
      successUrls.push(result.value)
    }
  }

  if (successUrls.length === 0) {
    throw new Error(
      `Failed to upload to any Blossom server. Tried: ${blossomUrls.join(', ')}`,
    )
  }

  return successUrls
}

/**
 * Download and decrypt an attachment from Blossom.
 *
 * Tries each Blossom URL in order until one succeeds.
 * Verifies the SHA-256 hash of the encrypted data before decrypting,
 * preventing tampered file content from being processed.
 *
 * @param attachment - The MailAttachment metadata (from parsed mail tags).
 * @returns The decrypted file data.
 * @throws If download fails from all URLs, hash mismatch, or decryption fails.
 */
export async function downloadAttachment(
  attachment: MailAttachment,
): Promise<Uint8Array> {
  if (!attachment.encryptionKey) {
    throw new Error('Attachment has no encryption key — cannot decrypt')
  }
  if (attachment.blossomUrls.length === 0) {
    throw new Error('No Blossom URLs available for this attachment')
  }

  const errors: string[] = []

  // Try each Blossom URL until one succeeds
  for (const blossomUrl of attachment.blossomUrls) {
    try {
      const encryptedData = await downloadFromBlossom(blossomUrl, attachment.hash)

      // Verify SHA-256 hash of the downloaded encrypted data
      const computedHash = bytesToHex(sha256(encryptedData))
      if (computedHash !== attachment.hash) {
        errors.push(
          `${blossomUrl}: hash mismatch (expected ${attachment.hash}, got ${computedHash})`,
        )
        continue // Try next URL — this server returned tampered data
      }

      // Decrypt the verified data
      const key = hexToBytes(attachment.encryptionKey)
      const decrypted = await decryptAesGcm(encryptedData, key)
      return decrypted
    } catch (err) {
      errors.push(
        `${blossomUrl}: ${err instanceof Error ? err.message : 'unknown error'}`,
      )
      continue
    }
  }

  throw new Error(
    `Failed to download attachment "${attachment.filename}" from all Blossom servers:\n${errors.join('\n')}`,
  )
}

/**
 * Download raw data from a Blossom server by hash.
 *
 * Blossom retrieval: GET /<sha256-hash>
 *
 * @param blossomUrl - Base URL of the Blossom server.
 * @param hash - SHA-256 hash of the file (hex encoded).
 * @returns Raw file bytes.
 */
async function downloadFromBlossom(blossomUrl: string, hash: string): Promise<Uint8Array> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), BLOSSOM_TIMEOUT_MS)

  try {
    const baseUrl = blossomUrl.replace(/\/+$/, '')
    const url = `${baseUrl}/${hash}`

    const response = await fetch(url, {
      signal: controller.signal,
    })

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }

    const buffer = await response.arrayBuffer()
    return new Uint8Array(buffer)
  } finally {
    clearTimeout(timeout)
  }
}
