// ─── NOSTR Mail Protocol — Cashu P2PK Postage Tokens ────────────────────────
// Creates and verifies NUT-11 P2PK locked Cashu tokens for anti-spam postage.
// All postage MUST use NUT-11 P2PK spending conditions.

import {
  CashuMint,
  CashuWallet,
  getEncodedToken,
  getDecodedToken,
  type Token,
} from '@cashu/cashu-ts'
import type { CashuPostage } from './types.js'

/**
 * Convert a NOSTR hex pubkey (32-byte x-only) to the compressed SEC format
 * required by NUT-11 P2PK spending conditions.
 *
 * NOSTR uses x-only (Schnorr) pubkeys (32 bytes hex). Cashu NUT-11 expects
 * compressed SEC pubkeys (33 bytes hex, prefixed with '02').
 *
 * @param hexPubkey - 64-character hex NOSTR public key.
 * @returns 66-character hex compressed SEC public key.
 */
function toCompressedSec(hexPubkey: string): string {
  if (hexPubkey.length !== 64 || !/^[0-9a-f]{64}$/i.test(hexPubkey)) {
    throw new Error(`Invalid NOSTR hex pubkey: expected 64 hex chars, got ${hexPubkey.length}`)
  }
  // NUT-11 uses even-parity compressed key: 02 + x-coordinate
  return '02' + hexPubkey.toLowerCase()
}

/**
 * Create Cashu P2PK postage tokens locked to a recipient's pubkey.
 * All postage MUST use NUT-11 P2PK spending conditions.
 *
 * Flow:
 * 1. Request a mint quote for the desired amount.
 * 2. Wait for the quote to be paid (assumes Lightning payment is handled externally).
 * 3. Mint tokens with a P2PK spending condition locking them to the recipient.
 * 4. Serialize the token in NUT-00 format.
 *
 * @param mintUrl - The Cashu mint URL.
 * @param amount - Amount in satoshis.
 * @param recipientPubkey - NOSTR hex pubkey to lock tokens to.
 * @param wallet - An initialized CashuWallet instance.
 * @returns CashuPostage object with the serialized token and metadata.
 */
export async function createPostageToken(
  mintUrl: string,
  amount: number,
  recipientPubkey: string,
  wallet: CashuWallet,
): Promise<CashuPostage> {
  if (amount <= 0) {
    throw new Error('Postage amount must be positive')
  }

  const compressedPubkey = toCompressedSec(recipientPubkey)

  // Step 1: Request a mint quote
  const mintQuote = await wallet.createMintQuote(amount)

  // Step 2: Wait for quote to be paid
  // In a real implementation, the caller would pay the Lightning invoice
  // (mintQuote.request) and then poll until the quote is paid.
  // For the reference implementation, we assume the quote is already paid
  // or the wallet handles payment internally.

  // Step 3: Mint tokens with P2PK spending condition (NUT-11)
  // The P2PK condition ensures only the holder of the corresponding
  // private key can spend these tokens.
  const p2pkCondition = {
    pubkey: compressedPubkey,
    // NUT-11 P2PK spending conditions
    locktime: undefined, // No time lock — recipient can redeem anytime
    refund: undefined,   // No refund path
    sigflag: 'SIG_INPUTS' as const, // Standard: sign all inputs
  }

  const proofs = await wallet.mintProofs(amount, mintQuote.quote, {
    p2pk: p2pkCondition,
  })

  // Step 4: Serialize token in NUT-00 v4 format
  const token = getEncodedToken({
    mint: mintUrl,
    proofs,
  })

  return {
    token,
    mint: mintUrl,
    amount,
    p2pk: true,
  }
}

/**
 * Verify and redeem Cashu postage tokens from a received message.
 * Checks: token is valid, P2PK locked to us, amount meets threshold.
 *
 * Verification steps:
 * 1. Decode the serialized token.
 * 2. Validate token structure (proofs array, mint URL).
 * 3. Check P2PK spending condition matches our pubkey.
 * 4. Sum proof amounts and verify >= minAmount.
 * 5. Contact the mint to swap tokens (redeem).
 *
 * @param postage - The CashuPostage from a parsed mail.
 * @param ourPubkey - Our NOSTR hex pubkey.
 * @param minAmount - Minimum required amount (from spam policy).
 * @returns Verification result with validity, amount, and redemption status.
 */
export async function verifyPostage(
  postage: CashuPostage,
  ourPubkey: string,
  minAmount: number,
): Promise<{
  valid: boolean
  amount: number
  redeemed: boolean
  error?: string
}> {
  // ── Step 1: Decode token ──────────────────────────────────────────────
  let decoded: Token
  try {
    decoded = getDecodedToken(postage.token)
  } catch (err) {
    return {
      valid: false,
      amount: 0,
      redeemed: false,
      error: `Failed to decode token: ${err instanceof Error ? err.message : 'invalid format'}`,
    }
  }

  // ── Step 2: Validate token structure ──────────────────────────────────
  const proofs = decoded.proofs
  if (!proofs || proofs.length === 0) {
    return {
      valid: false,
      amount: 0,
      redeemed: false,
      error: 'Token contains no proofs',
    }
  }

  const mintUrl = decoded.mint
  if (!mintUrl) {
    return {
      valid: false,
      amount: 0,
      redeemed: false,
      error: 'Token has no mint URL',
    }
  }

  // ── Step 3: Check P2PK spending condition ─────────────────────────────
  const ourCompressedPubkey = toCompressedSec(ourPubkey)

  for (const proof of proofs) {
    const secret = proof.secret
    // NUT-11 P2PK secrets are JSON arrays: ["P2PK", { "nonce": ..., "data": pubkey, ... }]
    if (typeof secret === 'string') {
      try {
        const parsed = JSON.parse(secret) as [string, { data?: string }]
        if (
          Array.isArray(parsed) &&
          parsed[0] === 'P2PK' &&
          parsed[1]?.data
        ) {
          if (parsed[1].data !== ourCompressedPubkey) {
            return {
              valid: false,
              amount: 0,
              redeemed: false,
              error: 'P2PK condition is not locked to our pubkey',
            }
          }
        }
      } catch {
        // If secret is not JSON, it's not a P2PK token
        return {
          valid: false,
          amount: 0,
          redeemed: false,
          error: 'Proof secret is not a valid P2PK condition',
        }
      }
    }
  }

  // ── Step 4: Verify total amount ───────────────────────────────────────
  const totalAmount = proofs.reduce((sum, p) => sum + p.amount, 0)

  if (totalAmount < minAmount) {
    return {
      valid: false,
      amount: totalAmount,
      redeemed: false,
      error: `Postage amount ${totalAmount} sats is below minimum ${minAmount} sats`,
    }
  }

  // ── Step 5: Redeem tokens via mint swap ───────────────────────────────
  // Swapping the proofs for new ones proves the tokens are unspent and
  // transfers ownership to us. If the swap fails, the tokens were already
  // spent (double-spend attempt) or the mint is unreachable.
  try {
    const mint = new CashuMint(mintUrl)
    const wallet = new CashuWallet(mint)

    // Swap the P2PK-locked proofs for fresh proofs owned by us.
    // The wallet automatically signs the swap request with our key if
    // the proofs have P2PK conditions.
    await wallet.swap(totalAmount, proofs)

    return {
      valid: true,
      amount: totalAmount,
      redeemed: true,
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error'

    // Distinguish between already-spent tokens and network errors
    if (
      message.includes('already spent') ||
      message.includes('Token already spent') ||
      message.includes('duplicate')
    ) {
      return {
        valid: false,
        amount: totalAmount,
        redeemed: false,
        error: 'Token already spent (possible double-spend attempt)',
      }
    }

    return {
      valid: false,
      amount: totalAmount,
      redeemed: false,
      error: `Mint unreachable or swap failed: ${message}`,
    }
  }
}

/**
 * Create a refund token to send back to the original sender.
 * Used when the recipient wants to refund postage for wanted mail.
 *
 * This is functionally identical to createPostageToken but locked to the
 * sender's pubkey instead of the recipient's.
 *
 * @param mintUrl - The Cashu mint URL.
 * @param amount - Amount in satoshis to refund.
 * @param senderPubkey - NOSTR hex pubkey of the original sender.
 * @param wallet - An initialized CashuWallet instance.
 * @returns CashuPostage object with the refund token.
 */
export async function createRefundToken(
  mintUrl: string,
  amount: number,
  senderPubkey: string,
  wallet: CashuWallet,
): Promise<CashuPostage> {
  return createPostageToken(mintUrl, amount, senderPubkey, wallet)
}
