import { Point, utils, getPublicKey } from '@noble/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3.js'

type WorkerMessage = {
  type: 'search'
  id: number
  batchSize: number
  prefixLower: string
  suffixLower: string
}

type WorkerResult = {
  type: 'result'
  id: number
  checked: number
  found: { privHex: string; address: string } | null
}

// Precomputed hex lookup table for fast conversion
const hexTable: string[] = new Array(256)
for (let i = 0; i < 256; i++) {
  hexTable[i] = i.toString(16).padStart(2, '0')
}

// Generator point and curve order for incremental key generation
const G = Point.BASE
const N = Point.CURVE().n

function pubkeyToAddress(pubkey64: Uint8Array): string {
  const hash = keccak_256(pubkey64)
  let addr = ''
  for (let i = 12; i < 32; i++) {
    addr += hexTable[hash[i]]
  }
  return addr
}

function bigIntToHex(n: bigint): string {
  return n.toString(16).padStart(64, '0')
}

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
  const { type, id, batchSize, prefixLower, suffixLower } = e.data

  if (type !== 'search') return

  // Generate random starting private key
  const privBytes = utils.randomSecretKey()
  let privKey = bytesToBigInt(privBytes)

  // Compute initial public key point (one full scalar multiplication)
  let pubPoint = Point.fromBytes(getPublicKey(privBytes, false))

  for (let i = 0; i < batchSize; i++) {
    // Convert point to uncompressed public key (64 bytes, no prefix)
    const pubRaw = pubPoint.toBytes(false)
    const pub64 = pubRaw.slice(1)
    const addr = pubkeyToAddress(pub64)

    if (addr.startsWith(prefixLower) && addr.endsWith(suffixLower)) {
      const result: WorkerResult = {
        type: 'result',
        id,
        checked: i + 1,
        found: { privHex: bigIntToHex(privKey), address: '0x' + addr }
      }
      self.postMessage(result)
      return
    }

    // Increment: add G to public key and +1 to private key (MUCH faster than full scalar mult)
    pubPoint = pubPoint.add(G)
    privKey = (privKey + 1n) % N
  }

  const result: WorkerResult = {
    type: 'result',
    id,
    checked: batchSize,
    found: null
  }
  self.postMessage(result)
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}
