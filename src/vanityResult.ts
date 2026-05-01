import { bytesToHex, hexToBytes } from './utils/hex'
import { checksumAddress, firstContractAddressFromWalletAddress, pubkeyToAddressBytes } from './wallet/ethAddress'
import { privateKeyToPublicKey64, type PrivKey32 } from './wallet/keys'
import type { SearchTarget } from './searchTarget'

export type VerifiedVanityResult = {
  priv: PrivKey32
  walletAddress: string
  targetAddress: string
}

function normalizeAddress(address: string): string | null {
  const hex = address.trim().replace(/^0x/i, '')
  if (!/^[0-9a-fA-F]{40}$/.test(hex)) return null
  return '0x' + hex.toLowerCase()
}

function normalizePrivateKey(privHex: string): PrivKey32 | null {
  const hex = privHex.trim().replace(/^0x/i, '')
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null
  try {
    return hexToBytes(hex) as PrivKey32
  } catch {
    return null
  }
}

export function deriveWalletAddressFromPriv(priv: PrivKey32): string {
  const pub64 = privateKeyToPublicKey64(priv)
  return checksumAddress('0x' + bytesToHex(pubkeyToAddressBytes(pub64)))
}

export function deriveTargetAddressFromPriv(priv: PrivKey32, target: SearchTarget): string {
  const walletAddress = deriveWalletAddressFromPriv(priv)
  return target === 'first-contract'
    ? checksumAddress(firstContractAddressFromWalletAddress(walletAddress))
    : walletAddress
}

export function addressMatchesRequest(
  address: string,
  prefix: string,
  suffix: string,
  caseSensitive: boolean
): boolean {
  const body = address.replace(/^0x/i, '')
  const prefixOk = caseSensitive
    ? body.startsWith(prefix)
    : body.toLowerCase().startsWith(prefix.toLowerCase())
  const suffixOk = caseSensitive
    ? body.endsWith(suffix)
    : body.toLowerCase().endsWith(suffix.toLowerCase())
  return prefixOk && suffixOk
}

export function verifyFoundResult(
  privHex: string,
  foundAddress: string,
  prefix: string,
  suffix: string,
  target: SearchTarget,
  caseSensitive: boolean
): VerifiedVanityResult | null {
  const priv = normalizePrivateKey(privHex)
  const normalizedFound = normalizeAddress(foundAddress)
  if (!priv || !normalizedFound) return null

  let walletAddress: string
  let targetAddress: string
  try {
    walletAddress = deriveWalletAddressFromPriv(priv)
    targetAddress = target === 'first-contract'
      ? checksumAddress(firstContractAddressFromWalletAddress(walletAddress))
      : walletAddress
  } catch {
    return null
  }

  if (normalizeAddress(targetAddress) !== normalizedFound) return null
  if (!addressMatchesRequest(targetAddress, prefix, suffix, caseSensitive)) return null

  return { priv, walletAddress, targetAddress }
}
