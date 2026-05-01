import { describe, expect, it } from 'vitest'
import { calculatePatternDifficulty, mergeAddressPattern } from './searchPattern'

describe('mergeAddressPattern', () => {
  it('accepts separate prefix and suffix constraints that fit in one address', () => {
    const pattern = mergeAddressPattern('c0ffee', 'beef', false)

    expect(pattern.valid).toBe(true)
    expect(pattern.constrainedNibbles).toBe(10)
    expect(pattern.body.slice(0, 6).join('')).toBe('c0ffee')
    expect(pattern.body.slice(-4).join('')).toBe('beef')
  })

  it('accepts compatible overlapping prefix and suffix constraints', () => {
    const pattern = mergeAddressPattern('a'.repeat(39), 'ab', false)

    expect(pattern.valid).toBe(true)
    expect(pattern.constrainedNibbles).toBe(40)
    expect(pattern.body.join('')).toBe('a'.repeat(39) + 'b')
  })

  it('rejects contradictory overlapping prefix and suffix constraints', () => {
    const pattern = mergeAddressPattern('a'.repeat(39), 'bb', false)

    expect(pattern.valid).toBe(false)
    expect(pattern.message).toMatch(/overlap/i)
  })

  it('treats case-sensitive overlapping constraints as exact', () => {
    expect(mergeAddressPattern('A'.repeat(39), 'ab', true).valid).toBe(false)
    expect(mergeAddressPattern('A'.repeat(39), 'Ab', true).valid).toBe(true)
  })
})

describe('calculatePatternDifficulty', () => {
  it('counts compatible overlap once instead of double-counting prefix plus suffix length', () => {
    expect(calculatePatternDifficulty('a'.repeat(39), 'ab', false)).toBe(16 ** 40)
  })

  it('returns Infinity for impossible constraints', () => {
    expect(calculatePatternDifficulty('a'.repeat(39), 'bb', false)).toBe(Infinity)
  })
})
