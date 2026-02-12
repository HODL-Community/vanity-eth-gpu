import { describe, expect, it } from 'vitest'
import { base58 } from '@scure/base'
import { keypairArrayFromPriv, secretKeyBase58FromPriv } from '../../src/wallet/keypairJson'
import { privateKeyToPublicKey32, privateKeyToSecretKey64, type PrivKey32 } from '../../src/wallet/keys'

function fixedPriv(): PrivKey32 {
  const priv = new Uint8Array(32)
  for (let i = 0; i < 32; i++) priv[i] = i + 1
  return priv as PrivKey32
}

describe('keys', () => {
  it('derives public key and 64-byte secret key from a private key seed', () => {
    const priv = fixedPriv()
    const publicKey = privateKeyToPublicKey32(priv)
    const secretKey = privateKeyToSecretKey64(priv)

    expect(publicKey).toHaveLength(32)
    expect(secretKey).toHaveLength(64)
    expect(Array.from(secretKey.slice(0, 32))).toEqual(Array.from(priv))
    expect(Array.from(secretKey.slice(32))).toEqual(Array.from(publicKey))
  })

  it('exports keypair formats consistently', () => {
    const priv = fixedPriv()
    const jsonArray = keypairArrayFromPriv(priv)
    const base58Secret = secretKeyBase58FromPriv(priv)

    expect(jsonArray).toHaveLength(64)
    expect(base58.decode(base58Secret)).toEqual(new Uint8Array(jsonArray))
  })
})
