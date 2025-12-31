import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex } from '../utils/hex'

export function pubkeyToAddressBytes(pubkey64: Uint8Array): Uint8Array {
  if (pubkey64.length !== 64) throw new Error('pubkey64 must be 64 bytes')
  const hash = keccak_256(pubkey64)
  return hash.slice(12) // last 20 bytes
}

export function checksumAddress(address: string): string {
  const addr = address.toLowerCase().replace(/^0x/, '')
  if (addr.length !== 40) throw new Error('Invalid address length')
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(addr)))
  let out = '0x'
  for (let i = 0; i < addr.length; i++) {
    const ch = addr[i]
    const h = parseInt(hash[i], 16)
    out += h >= 8 ? ch.toUpperCase() : ch
  }
  return out
}


