import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '../utils/hex'
import { bytesToBase58, matchesVanityTarget } from '../wallet/solanaAddress'
import type { SearchTarget } from '../searchTarget'

type WorkerMessage =
  | {
    type: 'search'
    id: number
    batchSize: number
    prefix: string
    suffix: string
    caseSensitive: boolean
    target: SearchTarget
  }
  | {
    type: 'generate'
    id: number
    batchSize: number
  }

type SearchWorkerResult = {
  type: 'result'
  id: number
  checked: number
  found: { privHex: string; address: string } | null
}

type BatchWorkerResult = {
  type: 'batch'
  id: number
  checked: number
  privKeys: Uint8Array
  pubKeys: Uint8Array
}

function generateBatch(batchSize: number): { privKeys: Uint8Array; pubKeys: Uint8Array } {
  const privKeys = new Uint8Array(batchSize * 32)
  const pubKeys = new Uint8Array(batchSize * 32)

  crypto.getRandomValues(privKeys)

  for (let i = 0; i < batchSize; i++) {
    const offset = i * 32
    const seed = privKeys.subarray(offset, offset + 32)
    const pubkey = ed25519.getPublicKey(seed)
    pubKeys.set(pubkey, offset)
  }

  return { privKeys, pubKeys }
}

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
  const message = e.data

  if (message.type === 'generate') {
    const { id, batchSize } = message
    const { privKeys, pubKeys } = generateBatch(batchSize)

    const result: BatchWorkerResult = {
      type: 'batch',
      id,
      checked: batchSize,
      privKeys,
      pubKeys,
    }

    self.postMessage(result)
    return
  }

  if (message.type !== 'search') return

  const { id, batchSize, prefix, suffix, caseSensitive, target } = message

  const { privKeys, pubKeys } = generateBatch(batchSize)

  for (let i = 0; i < batchSize; i++) {
    const offset = i * 32
    const seed = privKeys.subarray(offset, offset + 32)
    const pubkey = pubKeys.subarray(offset, offset + 32)
    const address = bytesToBase58(pubkey)

    // Program ID and wallet addresses are both Solana ed25519 pubkeys.
    const targetAddress = target === 'program' ? address : address

    if (!matchesVanityTarget(targetAddress, prefix, suffix, caseSensitive)) continue

    const verifyAddress = bytesToBase58(ed25519.getPublicKey(seed))
    if (verifyAddress !== targetAddress) continue

    const result: SearchWorkerResult = {
      type: 'result',
      id,
      checked: i + 1,
      found: {
        privHex: bytesToHex(seed),
        address: targetAddress,
      }
    }
    self.postMessage(result)
    return
  }

  const result: SearchWorkerResult = {
    type: 'result',
    id,
    checked: batchSize,
    found: null
  }
  self.postMessage(result)
}
