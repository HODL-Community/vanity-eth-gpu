import { describe, expect, it } from 'vitest'
import { checksumAddress } from './wallet/ethAddress'
import { hexToBytes } from './utils/hex'
import { deriveTargetAddressFromPriv, verifyFoundResult } from './vanityResult'
import type { PrivKey32 } from './wallet/keys'

const PRIV_ONE = '0000000000000000000000000000000000000000000000000000000000000001'
const WALLET_ONE = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'

describe('verifyFoundResult', () => {
  it('accepts a wallet result only when the private key derives to the displayed address and the request matches', () => {
    const result = verifyFoundResult(PRIV_ONE, checksumAddress(WALLET_ONE), '7e5f', 'bdf', 'wallet', false)

    expect(result).not.toBeNull()
    expect(result?.walletAddress.toLowerCase()).toBe(WALLET_ONE)
    expect(result?.targetAddress.toLowerCase()).toBe(WALLET_ONE)
  })

  it('rejects a wallet result when the displayed address does not derive from the private key', () => {
    const result = verifyFoundResult(
      PRIV_ONE,
      '0x0000000000000000000000000000000000000bdf',
      '0000',
      'bdf',
      'wallet',
      false
    )

    expect(result).toBeNull()
  })

  it('rejects a wallet result when it does not satisfy the requested prefix and suffix', () => {
    const result = verifyFoundResult(PRIV_ONE, checksumAddress(WALLET_ONE), 'dead', 'beef', 'wallet', false)

    expect(result).toBeNull()
  })

  it('accepts a first-contract result only when the private key derives to the displayed contract address', () => {
    const contractAddress = deriveTargetAddressFromPriv(hexToBytes(PRIV_ONE) as PrivKey32, 'first-contract')
    const result = verifyFoundResult(
      PRIV_ONE,
      contractAddress,
      contractAddress.slice(2, 6),
      contractAddress.slice(-3),
      'first-contract',
      false
    )

    expect(result).not.toBeNull()
    expect(result?.walletAddress.toLowerCase()).toBe(WALLET_ONE)
    expect(result?.targetAddress.toLowerCase()).toBe(contractAddress.toLowerCase())
  })
})
