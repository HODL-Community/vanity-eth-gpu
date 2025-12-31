import * as secp from '@noble/secp256k1'
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

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

function pubkeyToAddress(pubkey64: Uint8Array): string {
  const hash = keccak_256(pubkey64)
  return bytesToHex(hash.slice(12))
}

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
  const { type, id, batchSize, prefixLower, suffixLower } = e.data

  if (type !== 'search') return

  for (let i = 0; i < batchSize; i++) {
    const priv = secp.utils.randomSecretKey()
    const pub65 = secp.getPublicKey(priv, false)
    const pub64 = pub65.slice(1)
    const addr = pubkeyToAddress(pub64)

    if (addr.startsWith(prefixLower) && addr.endsWith(suffixLower)) {
      const result: WorkerResult = {
        type: 'result',
        id,
        checked: i + 1,
        found: { privHex: bytesToHex(priv), address: '0x' + addr }
      }
      self.postMessage(result)
      return
    }
  }

  const result: WorkerResult = {
    type: 'result',
    id,
    checked: batchSize,
    found: null
  }
  self.postMessage(result)
}
