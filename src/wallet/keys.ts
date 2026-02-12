import { ed25519 } from '@noble/curves/ed25519.js'

export type PrivKey32 = Uint8Array & { readonly __priv32: unique symbol }

export function randomPrivateKey(): PrivKey32 {
  const key = new Uint8Array(32)
  crypto.getRandomValues(key)
  return key as PrivKey32
}

export function privateKeyToPublicKey32(priv: PrivKey32): Uint8Array {
  return ed25519.getPublicKey(priv)
}

export function privateKeyToSecretKey64(priv: PrivKey32): Uint8Array {
  const secret = new Uint8Array(64)
  secret.set(priv, 0)
  secret.set(privateKeyToPublicKey32(priv), 32)
  return secret
}
