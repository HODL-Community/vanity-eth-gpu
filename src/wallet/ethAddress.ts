import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex } from '../utils/hex'

const hexTable: string[] = new Array(256)
for (let i = 0; i < 256; i++) {
  hexTable[i] = i.toString(16).padStart(2, '0')
}

const firstCreateInput = new Uint8Array(23)
firstCreateInput[0] = 0xd6
firstCreateInput[1] = 0x94
firstCreateInput[22] = 0x80

function hexNibbleFromCode(code: number): number {
  if (code >= 48 && code <= 57) return code - 48 // 0-9
  if (code >= 65 && code <= 70) return code - 55 // A-F
  if (code >= 97 && code <= 102) return code - 87 // a-f
  return -1
}

export function pubkeyToAddressBytes(pubkey64: Uint8Array): Uint8Array {
  if (pubkey64.length !== 64) throw new Error('pubkey64 must be 64 bytes')
  const hash = keccak_256(pubkey64)
  return hash.slice(12) // last 20 bytes
}

export function firstContractAddressFromWalletHex(walletHex40: string): string {
  if (walletHex40.length !== 40) throw new Error('Invalid wallet address length')

  for (let i = 0; i < 20; i++) {
    const hi = hexNibbleFromCode(walletHex40.charCodeAt(i * 2))
    const lo = hexNibbleFromCode(walletHex40.charCodeAt(i * 2 + 1))
    if (hi < 0 || lo < 0) throw new Error('Invalid wallet address hex')
    firstCreateInput[2 + i] = (hi << 4) | lo
  }

  const hash = keccak_256(firstCreateInput)
  let out = ''
  for (let i = 12; i < 32; i++) out += hexTable[hash[i]]
  return out
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
