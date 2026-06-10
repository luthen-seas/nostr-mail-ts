// Test helper: build real, structurally-valid cashuB P2PK tokens so spam-tier
// and conformance tests exercise the AUTHORITATIVE decode+verify path rather
// than the (removed) advisory-flag path.
import { getEncodedToken } from '@cashu/cashu-ts'
import type { CashuPostage } from '../../src/types.js'

/** Encode a P2PK token locked to `lockXonly` (64-hex x-only) with the given proof amounts. */
export function p2pkTokenString(
  mint: string,
  amounts: number[],
  lockXonly: string,
): string {
  const data = '02' + lockXonly.toLowerCase()
  const proofs = amounts.map((amount, i) => ({
    id: '009a1f293253e41e',
    amount,
    secret: JSON.stringify(['P2PK', { nonce: i.toString(16).padStart(64, '0'), data }]),
    C: '02' + 'a'.repeat(64),
  }))
  return getEncodedToken({ mint, unit: 'sat', proofs })
}

/** Encode a bearer (non-P2PK) token — its secret is a plain hex string. */
export function bearerTokenString(mint: string, amounts: number[]): string {
  const proofs = amounts.map((amount, i) => ({
    id: '009a1f293253e41e',
    amount,
    secret: 'b'.repeat(60) + i.toString(16).padStart(4, '0'),
    C: '02' + 'a'.repeat(64),
  }))
  return getEncodedToken({ mint, unit: 'sat', proofs })
}

/**
 * Build a CashuPostage with a real verified token. The advisory `amount`/`mint`
 * fields default to lies (so tests can prove they are ignored), but can be set.
 */
export function p2pkPostage(opts: {
  mint: string
  verified: number[]
  lockXonly: string
  claimAmount?: number
  claimMint?: string
}): CashuPostage {
  return {
    token: p2pkTokenString(opts.mint, opts.verified, opts.lockXonly),
    mint: opts.claimMint ?? opts.mint,
    amount: opts.claimAmount ?? opts.verified.reduce((a, b) => a + b, 0),
    p2pk: true,
  }
}
