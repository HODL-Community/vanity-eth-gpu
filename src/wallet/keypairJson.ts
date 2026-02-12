import { base58 } from '@scure/base'
import { privateKeyToSecretKey64, type PrivKey32 } from './keys'

export function secretKeyBase58FromPriv(priv: PrivKey32): string {
  return base58.encode(privateKeyToSecretKey64(priv))
}

export function keypairArrayFromPriv(priv: PrivKey32): number[] {
  return Array.from(privateKeyToSecretKey64(priv))
}
