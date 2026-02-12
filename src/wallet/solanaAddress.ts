import { base58 } from '@scure/base'

export const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_CHAR_SET = new Set(BASE58_ALPHABET)

export function bytesToBase58(bytes: Uint8Array): string {
  return base58.encode(bytes)
}

export function sanitizeBase58Input(input: string, maxLen = 44): string {
  let out = ''
  for (const ch of input.trim()) {
    if (BASE58_CHAR_SET.has(ch)) out += ch
    if (out.length >= maxLen) break
  }
  return out
}

function normalizeForMatch(input: string, caseSensitive: boolean): string {
  return caseSensitive ? input : input.toLowerCase()
}

export function matchesVanityTarget(address: string, prefix: string, suffix: string, caseSensitive: boolean): boolean {
  const addressValue = normalizeForMatch(address, caseSensitive)
  const prefixValue = normalizeForMatch(prefix, caseSensitive)
  const suffixValue = normalizeForMatch(suffix, caseSensitive)

  return addressValue.startsWith(prefixValue) && addressValue.endsWith(suffixValue)
}

export function hasCaseInsensitiveVariant(ch: string): boolean {
  if (!/[A-Za-z]/.test(ch)) return false
  const lower = ch.toLowerCase()
  const upper = ch.toUpperCase()
  return BASE58_CHAR_SET.has(lower) && BASE58_CHAR_SET.has(upper)
}
