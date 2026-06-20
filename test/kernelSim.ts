// Faithful JS simulation of src/webgpu/secp256k1.wgsl (the GPU kernel),
// emulating WGSL u32 wraparound semantics exactly. Used as a differential
// reference so the hand-rolled GPU crypto can be tested against @noble in Node.
//
// This mirrors the FIXED kernel (correct mod_mul carry + multi-fold reduction,
// correct EC doubling Z3, correct Keccak RC_HI). If the WGSL and this sim ever
// disagree with @noble, one of them regressed.

type Limbs = number[] // 8 x u32, little-endian (limb[0] = least significant)

const u32 = (x: number) => x >>> 0
const shl16 = (a: number) => (((a >>> 0) * 65536) % 4294967296) >>> 0

export const P: Limbs = [0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff].map(u32)

function mul32(a: number, b: number) {
  a = u32(a); b = u32(b)
  const al = a & 0xffff, ah = a >>> 16
  const bl = b & 0xffff, bh = b >>> 16
  const p0 = al * bl, p1 = al * bh, p2 = ah * bl, p3 = ah * bh
  const mid = u32(p1 + p2)
  const mid_c = mid < p1 ? 0x10000 : 0
  const lo = u32(p0 + shl16(mid))
  const lo_c = lo < p0 ? 1 : 0
  const hi = u32(p3 + (mid >>> 16) + mid_c + lo_c)
  return { x: lo, y: hi }
}
function gte_p(a: Limbs) { for (let i = 7; i >= 0; i--) { if (a[i] > P[i]) return true; if (a[i] < P[i]) return false } return true }
function sub_p(a: Limbs) { let borrow = 0; for (let i = 0; i < 8; i++) { const t = u32(a[i] - P[i] - borrow); borrow = a[i] < P[i] + borrow ? 1 : 0; a[i] = t } }
function addP(a: Limbs) { let carry = 0; for (let i = 0; i < 8; i++) { const s0 = u32(a[i] + P[i]); const k0 = s0 < a[i] ? 1 : 0; const s1 = u32(s0 + carry); const k1 = s1 < s0 ? 1 : 0; a[i] = s1; carry = k0 + k1 } }
function add256(a: Limbs, b: Limbs) { const c: Limbs = new Array(8); let carry = 0; for (let i = 0; i < 8; i++) { const s0 = u32(a[i] + b[i]); const k0 = s0 < a[i] ? 1 : 0; const s1 = u32(s0 + carry); const k1 = s1 < s0 ? 1 : 0; c[i] = s1; carry = k0 + k1 } return { c, carry } }
function sub256(a: Limbs, b: Limbs) { const c: Limbs = new Array(8); let borrow = 0; for (let i = 0; i < 8; i++) { const bi = u32(b[i] + borrow); const nb = a[i] < b[i] + borrow ? 1 : 0; c[i] = u32(a[i] - bi); borrow = nb } return { c, borrow } }
function modAdd(a: Limbs, b: Limbs) { const { c, carry } = add256(a, b); if (carry === 1 || gte_p(c)) sub_p(c); return c }
function modSub(a: Limbs, b: Limbs) { const { c, borrow } = sub256(a, b); if (borrow === 1) addP(c); return c }

export function modMul(A: Limbs, B: Limbs): Limbs {
  const prod = new Array(16).fill(0)
  for (let i = 0; i < 8; i++) {
    let carry = 0
    for (let j = 0; j < 8; j++) {
      const m = mul32(A[i], B[j])
      const s0 = u32(m.x + prod[i + j]); const k0 = s0 < m.x ? 1 : 0
      const s1 = u32(s0 + carry); const k1 = s1 < s0 ? 1 : 0
      prod[i + j] = s1; carry = u32(m.y + k0 + k1)
    }
    prod[i + 8] = carry
  }
  const w = prod.slice()
  let any = true
  while (any) {
    const H = w.slice(8, 16)
    for (let i = 8; i < 16; i++) w[i] = 0
    let carry = 0
    for (let i = 0; i < 8; i++) {
      const m = mul32(H[i], 977)
      const s0 = u32(w[i] + m.x); const k0 = s0 < m.x ? 1 : 0
      const s1 = u32(s0 + carry); const k1 = s1 < s0 ? 1 : 0
      w[i] = s1; carry = u32(m.y + k0 + k1)
    }
    let idx = 8
    while (carry > 0 && idx < 16) { const s = u32(w[idx] + carry); const k = s < w[idx] ? 1 : 0; w[idx] = s; carry = k; idx++ }
    carry = 0
    for (let i = 0; i < 8; i++) {
      const s0 = u32(w[i + 1] + H[i]); const k0 = s0 < H[i] ? 1 : 0
      const s1 = u32(s0 + carry); const k1 = s1 < s0 ? 1 : 0
      w[i + 1] = s1; carry = u32(k0 + k1)
    }
    idx = 9
    while (carry > 0 && idx < 16) { const s = u32(w[idx] + carry); const k = s < w[idx] ? 1 : 0; w[idx] = s; carry = k; idx++ }
    any = false
    for (let i = 8; i < 16; i++) if (w[i] !== 0) { any = true; break }
  }
  const c = w.slice(0, 8)
  while (gte_p(c)) sub_p(c)
  return c
}
const modSqr = (a: Limbs) => modMul(a, a)
function modInv(a: Limbs): Limbs {
  let result: Limbs = [1, 0, 0, 0, 0, 0, 0, 0]
  let base = a.slice()
  const exp = [0xfffffc2d, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff].map(u32)
  for (let i = 0; i < 256; i++) {
    const limb = i >>> 5, bit = i & 31
    if ((exp[limb] & (1 << bit)) !== 0) result = modMul(result, base)
    base = modSqr(base)
  }
  return result
}

// ---- BigInt <-> limbs ----
export const P_BIG = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export function bigToLimbs(v: bigint): Limbs { const a: Limbs = new Array(8); for (let i = 0; i < 8; i++) { a[i] = Number(v & 0xffffffffn); v >>= 32n } return a }
export function limbsToBig(a: Limbs): bigint { let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 32n) | BigInt(a[i] >>> 0); return v }
export const fieldOps = { modMul, modAdd, modSqr, modSub, modInv }

// ---- EC (Jacobian) ----
const G = {
  x: [0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e].map(u32),
  y: [0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77].map(u32),
}
const ZERO8 = (): Limbs => [0, 0, 0, 0, 0, 0, 0, 0]
const ONE8 = (): Limbs => [1, 0, 0, 0, 0, 0, 0, 0]
const isZero8 = (a: Limbs) => a.every(x => x === 0)
let gx: Limbs, gy: Limbs, gz: Limbs, rx: Limbs, ry: Limbs, rz: Limbs
function pointDoubleG() {
  if (isZero8(gz)) return
  const z3 = modAdd(modMul(gy, gz), modMul(gy, gz)) // 2*Y1*Z1 (original)
  const xx = modSqr(gx), yy = modSqr(gy), yyyy = modSqr(yy)
  let t1 = modAdd(gx, yy), t2 = modSqr(t1)
  t1 = modSub(t2, xx); t2 = modSub(t1, yyyy)
  const s = modAdd(t2, t2)
  t1 = modAdd(xx, xx); const m = modAdd(t1, xx)
  t1 = modSqr(m); t2 = modAdd(s, s); gx = modSub(t1, t2)
  t1 = modSub(s, gx); t2 = modMul(m, t1)
  t1 = modAdd(yyyy, yyyy); let t3 = modAdd(t1, t1); t1 = modAdd(t3, t3)
  gy = modSub(t2, t1); gz = z3
}
function pointAddRG() {
  if (isZero8(rz)) { rx = gx.slice(); ry = gy.slice(); rz = gz.slice(); return }
  if (isZero8(gz)) return
  const z1z1 = modSqr(rz), z2z2 = modSqr(gz)
  const u1 = modMul(rx, z2z2), u2 = modMul(gx, z1z1)
  let t1 = modMul(gz, z2z2); const s1 = modMul(ry, t1)
  t1 = modMul(rz, z1z1); const s2 = modMul(gy, t1)
  const h = modSub(u2, u1), r = modSub(s2, s1)
  const hh = modSqr(h), hhh = modMul(h, hh), u1hh = modMul(u1, hh)
  t1 = modSqr(r); let t2 = modAdd(u1hh, u1hh); let t3 = modAdd(hhh, t2)
  rx = modSub(t1, t3); t1 = modSub(u1hh, rx); t2 = modMul(r, t1); t1 = modMul(s1, hhh)
  ry = modSub(t2, t1); t1 = modMul(rz, gz); rz = modMul(t1, h)
}
function scalarMult(k: Limbs) {
  rx = ZERO8(); ry = ZERO8(); rz = ZERO8(); gx = G.x.slice(); gy = G.y.slice(); gz = ONE8()
  for (let i = 0; i < 256; i++) { const limb = i >>> 5, bit = i & 31; if ((k[limb] & (1 << bit)) !== 0) pointAddRG(); pointDoubleG() }
}
function toAffine() {
  if (isZero8(rz)) return { ax: ZERO8(), ay: ZERO8() }
  const zinv = modInv(rz), zinv2 = modSqr(zinv), zinv3 = modMul(zinv2, zinv)
  return { ax: modMul(rx, zinv2), ay: modMul(ry, zinv3) }
}

// ---- Keccak (50-u32 state, mirrors the WGSL) ----
export const RC_LO = [0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008].map(u32)
export const RC_HI = [0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000].map(u32)
const PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
const ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
function rotl64(lo: number, hi: number, n: number) {
  if (n === 0) return [lo, hi]
  if (n < 32) return [u32((lo << n) | (hi >>> (32 - n))), u32((hi << n) | (lo >>> (32 - n)))]
  const m = n - 32
  return [u32((hi << m) | (lo >>> (32 - m))), u32((lo << m) | (hi >>> (32 - m)))]
}
let state: number[]
function keccakPermute() {
  for (let round = 0; round < 24; round++) {
    const c = new Array(10)
    for (let x = 0; x < 5; x++) {
      c[x * 2] = u32(state[x * 2] ^ state[10 + x * 2] ^ state[20 + x * 2] ^ state[30 + x * 2] ^ state[40 + x * 2])
      c[x * 2 + 1] = u32(state[x * 2 + 1] ^ state[10 + x * 2 + 1] ^ state[20 + x * 2 + 1] ^ state[30 + x * 2 + 1] ^ state[40 + x * 2 + 1])
    }
    for (let x = 0; x < 5; x++) {
      const x1 = (x + 1) % 5, x4 = (x + 4) % 5
      const rot = rotl64(c[x1 * 2], c[x1 * 2 + 1], 1)
      const d0 = u32(c[x4 * 2] ^ rot[0]); const d1 = u32(c[x4 * 2 + 1] ^ rot[1])
      for (let y = 0; y < 5; y++) { const idx = (y * 5 + x) * 2; state[idx] = u32(state[idx] ^ d0); state[idx + 1] = u32(state[idx + 1] ^ d1) }
    }
    const temp = new Array(50).fill(0)
    temp[0] = state[0]; temp[1] = state[1]
    let t0 = state[2], t1 = state[3]
    for (let i = 0; i < 24; i++) { const j = PILN[i]; const n0 = state[j * 2], n1 = state[j * 2 + 1]; const rot = rotl64(t0, t1, ROTC[i]); temp[j * 2] = rot[0]; temp[j * 2 + 1] = rot[1]; t0 = n0; t1 = n1 }
    for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
      const i0 = (y * 5 + x) * 2, i1 = (y * 5 + ((x + 1) % 5)) * 2, i2 = (y * 5 + ((x + 2) % 5)) * 2
      state[i0] = u32(temp[i0] ^ ((~temp[i1]) & temp[i2])); state[i0 + 1] = u32(temp[i0 + 1] ^ ((~temp[i1 + 1]) & temp[i2 + 1]))
    }
    state[0] = u32(state[0] ^ RC_LO[round]); state[1] = u32(state[1] ^ RC_HI[round])
  }
}
const stateByte = (bi: number) => (state[bi >> 2] >>> ((bi & 3) * 8)) & 0xff

/** keccak256 of an arbitrary byte array, using the kernel's 50-u32 permutation. */
export function keccak256(msg: Uint8Array): string {
  const rate = 136
  state = new Array(50).fill(0)
  // single block only (enough for <=135-byte messages used here)
  for (let i = 0; i < msg.length; i++) { const bi = i; state[bi >> 2] = u32(state[bi >> 2] ^ (msg[i] << ((bi & 3) * 8))) }
  state[msg.length >> 2] = u32(state[msg.length >> 2] ^ (0x01 << ((msg.length & 3) * 8)))
  const last = rate - 1
  state[last >> 2] = u32(state[last >> 2] ^ (0x80 << ((last & 3) * 8)))
  keccakPermute()
  let h = ''
  for (let i = 0; i < 32; i++) h += stateByte(i).toString(16).padStart(2, '0')
  return h
}

/** Derive the 40-char lowercase Ethereum address from a private scalar (LE limbs), exactly as the kernel does. */
export function deriveAddressLE(kLimbs: Limbs): string {
  scalarMult(kLimbs)
  const { ax, ay } = toAffine()
  const pub16 = new Array(16)
  for (let i = 0; i < 8; i++) {
    const vx = ax[7 - i], vy = ay[7 - i]
    pub16[i] = u32(((vx & 0xff) << 24) | ((vx & 0xff00) << 8) | ((vx >>> 8) & 0xff00) | ((vx >>> 24) & 0xff))
    pub16[8 + i] = u32(((vy & 0xff) << 24) | ((vy & 0xff00) << 8) | ((vy >>> 8) & 0xff00) | ((vy >>> 24) & 0xff))
  }
  state = new Array(50).fill(0)
  for (let i = 0; i < 16; i++) state[i] = pub16[i]
  state[16] = u32(state[16] ^ 0x01)
  state[33] = u32(state[33] ^ 0x80000000)
  keccakPermute()
  let addr = ''
  for (let i = 12; i < 32; i++) addr += stateByte(i).toString(16).padStart(2, '0')
  return addr
}

/** Canonical Keccak-f[1600] round constants, for asserting the WGSL tables. */
export const CANONICAL_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
]
