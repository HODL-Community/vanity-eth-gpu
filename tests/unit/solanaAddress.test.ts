import { describe, expect, it } from 'vitest'
import {
  bytesToBase58,
  hasCaseInsensitiveVariant,
  matchesVanityTarget,
  sanitizeBase58Input,
} from '../../src/wallet/solanaAddress'

describe('solanaAddress', () => {
  it('sanitizes to valid Base58 characters with max length', () => {
    expect(sanitizeBase58Input('  0OIlabcXYZ123  ')).toBe('abcXYZ123')
    expect(sanitizeBase58Input('abcd', 2)).toBe('ab')
  })

  it('matches vanity targets with and without case sensitivity', () => {
    const address = 'AbCdEF123xyZ'

    expect(matchesVanityTarget(address, 'AbC', 'xyZ', true)).toBe(true)
    expect(matchesVanityTarget(address, 'abc', 'xyz', true)).toBe(false)
    expect(matchesVanityTarget(address, 'abc', 'xyz', false)).toBe(true)
  })

  it('detects case-insensitive variants only when both variants are in Base58 alphabet', () => {
    expect(hasCaseInsensitiveVariant('Z')).toBe(true)
    expect(hasCaseInsensitiveVariant('b')).toBe(true)
    expect(hasCaseInsensitiveVariant('o')).toBe(false)
    expect(hasCaseInsensitiveVariant('0')).toBe(false)
  })

  it('encodes bytes to Base58 known values', () => {
    expect(bytesToBase58(new Uint8Array([0]))).toBe('1')
    expect(bytesToBase58(new Uint8Array([1]))).toBe('2')
  })
})
