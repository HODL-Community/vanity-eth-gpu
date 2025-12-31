import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { ctr } from '@noble/ciphers/aes.js'
import { bytesToHex } from '../utils/hex'
import { privateKeyToPublicKey64, type PrivKey32 } from './keys'
import { pubkeyToAddressBytes } from './ethAddress'

export type KeystoreV3 = {
  version: 3
  id: string
  address: string
  crypto: {
    ciphertext: string
    cipherparams: { iv: string }
    cipher: 'aes-128-ctr'
    kdf: 'pbkdf2'
    kdfparams: {
      dklen: 32
      c: 65536
      prf: 'hmac-sha256'
      salt: string
    }
    mac: string
  }
}

function uuidv4(): string {
  return window.crypto.randomUUID()
}

export async function createKeystoreV3(priv: PrivKey32, password: string): Promise<KeystoreV3> {
  const salt = new Uint8Array(32)
  window.crypto.getRandomValues(salt)
  const iv = new Uint8Array(16)
  window.crypto.getRandomValues(iv)

  const dk = await pbkdf2Async(sha256, password, salt, { c: 65536, dkLen: 32 })
  const key = dk.slice(0, 16)

  const aes = ctr(key, iv)
  const ciphertext = aes.encrypt(priv)

  const macInput = new Uint8Array(16 + ciphertext.length)
  macInput.set(dk.slice(16, 32), 0)
  macInput.set(ciphertext, 16)
  const mac = keccak_256(macInput)

  const pub64 = privateKeyToPublicKey64(priv)
  const addr = pubkeyToAddressBytes(pub64) // 20 bytes

  return {
    version: 3,
    id: uuidv4(),
    address: bytesToHex(addr),
    crypto: {
      ciphertext: bytesToHex(ciphertext),
      cipherparams: { iv: bytesToHex(iv) },
      cipher: 'aes-128-ctr',
      kdf: 'pbkdf2',
      kdfparams: {
        dklen: 32,
        c: 65536,
        prf: 'hmac-sha256',
        salt: bytesToHex(salt),
      },
      mac: bytesToHex(mac),
    },
  }
}



