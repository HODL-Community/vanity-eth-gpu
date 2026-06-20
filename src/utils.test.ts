import { describe, expect, it } from 'vitest'
import { hexToBytes } from './utils/hex'
import { checksumAddress } from './wallet/ethAddress'

describe('hex helpers', () => {
  it('rejects non-hex characters instead of coercing them to zero bytes', () => {
    expect(() => hexToBytes('zz')).toThrow(/invalid hex/i)
  })

  it('rejects odd-length hex strings', () => {
    expect(() => hexToBytes('abc')).toThrow(/length/i)
  })

  it('checksumAddress rejects non-hex address bodies', () => {
    expect(() => checksumAddress('0x' + 'g'.repeat(40))).toThrow(/hex/i)
  })
})
