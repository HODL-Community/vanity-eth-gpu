import { describe, it, expect } from 'vitest'
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { scryptAsync } from '@noble/hashes/scrypt.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { ctr } from '@noble/ciphers/aes.js'
import { checksumAddress, firstContractAddressFromWalletHex, pubkeyToAddressBytes } from '../src/wallet/ethAddress'
import { createKeystoreV3 } from '../src/wallet/keystoreV3'
import { privateKeyToPublicKey64, type PrivKey32 } from '../src/wallet/keys'
import { hexToBytes, bytesToHex } from '../src/utils/hex'

describe('EIP-55 checksum', () => {
  // Canonical vectors from EIP-55.
  const vectors = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]
  it('produces the canonical mixed-case form from a lowercase address', () => {
    for (const v of vectors) {
      expect(checksumAddress(v.toLowerCase())).toBe(v)
      expect(checksumAddress(v)).toBe(v) // idempotent
    }
  })
})

describe('CREATE (nonce 0) contract address', () => {
  // Classic ethereumjs vector: deployer 0x6ac7ea33...dbf0, nonce 0.
  const deployer = '6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0'
  it('matches the known nonce-0 deployment address', () => {
    expect(firstContractAddressFromWalletHex(deployer)).toBe('cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d')
  })
  it('is correct across repeated calls (module-level buffer is not corrupted)', () => {
    const a = firstContractAddressFromWalletHex(deployer)
    const other = '0000000000000000000000000000000000000000'
    firstContractAddressFromWalletHex(other) // different input between
    expect(firstContractAddressFromWalletHex(deployer)).toBe(a)
  })
})

describe('pubkeyToAddressBytes', () => {
  it('derives the all-ones-ish known key address', () => {
    // priv = 1 -> generator pubkey -> known address
    const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001') as PrivKey32
    const pub64 = privateKeyToPublicKey64(priv)
    const addr = bytesToHex(pubkeyToAddressBytes(pub64))
    expect(addr).toBe('7e5f4552091a69125d5dfcb7b8c2659029395bdf')
  })
})

describe('Keystore V3 round-trip', () => {
  it('encrypts a key that decrypts back and has a valid MAC + address', async () => {
    const priv = hexToBytes('4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318') as PrivKey32
    const ks = await createKeystoreV3(priv, 'correct horse battery staple')

    // Derive the KDF key the same way the keystore did, honoring whichever KDF it emitted.
    const salt = hexToBytes(ks.crypto.kdfparams.salt)
    const kp = ks.crypto.kdfparams as any
    let dk: Uint8Array
    if (ks.crypto.kdf === 'scrypt') {
      dk = await scryptAsync('correct horse battery staple', salt, { N: kp.n, r: kp.r, p: kp.p, dkLen: kp.dklen })
    } else {
      dk = await pbkdf2Async(sha256, 'correct horse battery staple', salt, { c: kp.c, dkLen: kp.dklen })
    }

    const ciphertext = hexToBytes(ks.crypto.ciphertext)
    // MAC = keccak256(dk[16:32] || ciphertext)
    const macInput = new Uint8Array(16 + ciphertext.length)
    macInput.set(dk.slice(16, 32), 0)
    macInput.set(ciphertext, 16)
    expect(bytesToHex(keccak_256(macInput))).toBe(ks.crypto.mac)

    // Decrypt and confirm we recover the original private key.
    const iv = hexToBytes(ks.crypto.cipherparams.iv)
    const decrypted = ctr(dk.slice(0, 16), iv).decrypt(ciphertext)
    expect(bytesToHex(decrypted)).toBe(bytesToHex(priv))

    // The stored address must match the key.
    const pub64 = privateKeyToPublicKey64(priv)
    expect(ks.address).toBe(bytesToHex(pubkeyToAddressBytes(pub64)))
  })
})
