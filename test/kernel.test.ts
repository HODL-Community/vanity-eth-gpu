import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import * as secp from '@noble/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3.js'
import {
  modMul, bigToLimbs, limbsToBig, P_BIG, deriveAddressLE, keccak256,
  RC_LO, RC_HI, CANONICAL_RC,
} from './kernelSim'

const here = dirname(fileURLToPath(import.meta.url))
const wgslPath = join(here, '..', 'src', 'webgpu', 'secp256k1.wgsl')

function randBig(): bigint {
  let v = 0n
  for (let i = 0; i < 8; i++) v = (v << 32n) | BigInt((Math.random() * 4294967296) >>> 0)
  return v % P_BIG
}
function bigToBE32(v: bigint): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n }
  return out
}
function nobleAddress(priv: Uint8Array): string {
  const pub64 = secp.getPublicKey(priv, false).slice(1)
  return Buffer.from(keccak_256(pub64).slice(12)).toString('hex')
}

// Pull RC_LO / RC_HI out of the actual shader source and rebuild the 64-bit constants.
function shaderRoundConstants(): bigint[] {
  const src = readFileSync(wgslPath, 'utf8')
  const grab = (name: string) => {
    const m = src.match(new RegExp(`const\\s+${name}\\s*:[^=]*=\\s*array<u32,\\s*24>\\s*\\(([^)]*)\\)`))
    if (!m) throw new Error(`could not find ${name} in shader`)
    const vals = m[1].match(/0x[0-9a-fA-F]+/g)!.map(h => BigInt(h))
    if (vals.length !== 24) throw new Error(`${name} expected 24 values, got ${vals.length}`)
    return vals
  }
  const lo = grab('RC_LO'), hi = grab('RC_HI')
  return lo.map((l, i) => (hi[i] << 32n) | l)
}

describe('GPU kernel field arithmetic (mod_mul)', () => {
  it('matches BigInt (A*B) mod p over many random + adversarial inputs', () => {
    const adversarial: [bigint, bigint][] = [
      [P_BIG - 1n, P_BIG - 1n],
      [P_BIG - 1n, 2n],
      [1n << 255n, 1n << 255n],
      [0n, P_BIG - 1n],
      [1n, P_BIG - 1n],
    ]
    let fails = 0
    for (const [A, B] of adversarial) {
      if (limbsToBig(modMul(bigToLimbs(A), bigToLimbs(B))) !== (A * B) % P_BIG) fails++
    }
    for (let t = 0; t < 30000; t++) {
      const A = randBig(), B = randBig()
      if (limbsToBig(modMul(bigToLimbs(A), bigToLimbs(B))) !== (A * B) % P_BIG) fails++
    }
    expect(fails).toBe(0)
  })
})

describe('GPU kernel Keccak', () => {
  it('produces the canonical keccak256("") digest', () => {
    expect(keccak256(new Uint8Array(0))).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
  })

  it('the shader RC_LO/RC_HI tables equal the canonical Keccak round constants', () => {
    // Guards the exact bug class that was shipped: a wrong RC_HI entry silently
    // corrupts the permutation and yields wrong addresses.
    const fromShader = shaderRoundConstants()
    expect(fromShader).toEqual(CANONICAL_RC)
    // And the sim's copy must agree too.
    const fromSim = RC_LO.map((l, i) => (BigInt(RC_HI[i] >>> 0) << 32n) | BigInt(l >>> 0))
    expect(fromSim).toEqual(CANONICAL_RC)
  })
})

describe('GPU kernel full address derivation', () => {
  it('matches @noble end-to-end for many random private keys', () => {
    let fails = 0
    for (let t = 0; t < 250; t++) {
      let k = randBig()
      if (k === 0n) k = 1n
      const priv = bigToBE32(k)
      const got = deriveAddressLE(bigToLimbs(k))
      const exp = nobleAddress(priv)
      if (got !== exp) fails++
    }
    expect(fails).toBe(0)
  })

  it('matches @noble for known edge-case scalars (1, 2, n-1)', () => {
    const n = (secp as any).CURVE?.n ?? (secp as any).Point?.CURVE?.()?.n
    const cases = [1n, 2n, 3n]
    if (typeof n === 'bigint') cases.push(n - 1n)
    for (const k of cases) {
      const got = deriveAddressLE(bigToLimbs(k))
      const exp = nobleAddress(bigToBE32(k))
      expect(got, `scalar ${k}`).toBe(exp)
    }
  })
})
