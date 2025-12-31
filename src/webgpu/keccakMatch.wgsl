// Keccak-256(pubkey64) and match prefix/suffix (lowercase hex nibbles).
// Each invocation handles one 64-byte pubkey (x||y), computes address = last 20 bytes of hash,
// and if it matches, writes the index to the matches buffer.

const MAX_PREFIX: u32 = 40u;
const MAX_SUFFIX: u32 = 40u;
const MAX_MATCHES: u32 = 1024u;

struct U64 { lo: u32, hi: u32 };

fn u64_xor(a: U64, b: U64) -> U64 { return U64(a.lo ^ b.lo, a.hi ^ b.hi); }
fn u64_and(a: U64, b: U64) -> U64 { return U64(a.lo & b.lo, a.hi & b.hi); }
fn u64_not(a: U64) -> U64 { return U64(~a.lo, ~a.hi); }

fn u64_rotl(a: U64, n: u32) -> U64 {
  if (n == 0u) { return a; }
  if (n < 32u) {
    let lo = (a.lo << n) | (a.hi >> (32u - n));
    let hi = (a.hi << n) | (a.lo >> (32u - n));
    return U64(lo, hi);
  }
  if (n == 32u) { return U64(a.hi, a.lo); }
  let k = n - 32u;
  let lo = (a.hi << k) | (a.lo >> (32u - k));
  let hi = (a.lo << k) | (a.hi >> (32u - k));
  return U64(lo, hi);
}

fn u64_from_u32(x: u32) -> U64 { return U64(x, 0u); }

fn u64_byte_at_le(a: U64, byteIndex: u32) -> u32 {
  // byteIndex 0..7, little-endian
  if (byteIndex < 4u) {
    return (a.lo >> (8u * byteIndex)) & 0xffu;
  }
  let b = byteIndex - 4u;
  return (a.hi >> (8u * b)) & 0xffu;
}

const R: array<u32, 25> = array<u32, 25>(
  0u,  1u, 62u, 28u, 27u,
  36u, 44u,  6u, 55u, 20u,
  3u, 10u, 43u, 25u, 39u,
  41u, 45u, 15u, 21u,  8u,
  18u,  2u, 61u, 56u, 14u
);

const RC_LO: array<u32, 24> = array<u32, 24>(
  0x00000001u, 0x00008082u, 0x0000808Au, 0x80008000u,
  0x0000808Bu, 0x80000001u, 0x80008081u, 0x00008009u,
  0x0000008Au, 0x00000088u, 0x80008009u, 0x8000000Au,
  0x8000808Bu, 0x0000008Bu, 0x00008089u, 0x00008003u,
  0x00008002u, 0x00000080u, 0x0000800Au, 0x8000000Au,
  0x80008081u, 0x00008080u, 0x80000001u, 0x80008008u
);

const RC_HI: array<u32, 24> = array<u32, 24>(
  0x00000000u, 0x00000000u, 0x80000000u, 0x80000000u,
  0x00000000u, 0x00000000u, 0x80000000u, 0x00000000u,
  0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
  0x00000000u, 0x80000000u, 0x80000000u, 0x80000000u,
  0x80000000u, 0x80000000u, 0x00000000u, 0x80000000u,
  0x80000000u, 0x80000000u, 0x00000000u, 0x80000000u
);

fn keccak_f1600(state: ptr<function, array<U64, 25>>) {
  for (var round: u32 = 0u; round < 24u; round = round + 1u) {
    var C: array<U64, 5>;
    for (var x: u32 = 0u; x < 5u; x = x + 1u) {
      C[x] = u64_xor(u64_xor(u64_xor(u64_xor((*state)[x], (*state)[x + 5u]), (*state)[x + 10u]), (*state)[x + 15u]), (*state)[x + 20u]);
    }
    var D: array<U64, 5>;
    for (var x2: u32 = 0u; x2 < 5u; x2 = x2 + 1u) {
      D[x2] = u64_xor(C[(x2 + 4u) % 5u], u64_rotl(C[(x2 + 1u) % 5u], 1u));
    }
    for (var i: u32 = 0u; i < 25u; i = i + 1u) {
      (*state)[i] = u64_xor((*state)[i], D[i % 5u]);
    }

    // Rho + Pi
    var B: array<U64, 25>;
    for (var x3: u32 = 0u; x3 < 5u; x3 = x3 + 1u) {
      for (var y3: u32 = 0u; y3 < 5u; y3 = y3 + 1u) {
        let idx = x3 + 5u * y3;
        let rot = R[idx];
        let v = u64_rotl((*state)[idx], rot);
        let nx = y3;
        let ny = (2u * x3 + 3u * y3) % 5u;
        B[nx + 5u * ny] = v;
      }
    }

    // Chi
    for (var y4: u32 = 0u; y4 < 5u; y4 = y4 + 1u) {
      for (var x4: u32 = 0u; x4 < 5u; x4 = x4 + 1u) {
        let idx = x4 + 5u * y4;
        let a = B[idx];
        let b = B[((x4 + 1u) % 5u) + 5u * y4];
        let c = B[((x4 + 2u) % 5u) + 5u * y4];
        (*state)[idx] = u64_xor(a, u64_and(u64_not(b), c));
      }
    }

    // Iota
    (*state)[0] = u64_xor((*state)[0], U64(RC_LO[round], RC_HI[round]));
  }
}

struct Params {
  prefixLen: u32,
  suffixLen: u32,
  _pad0: u32,
  _pad1: u32,
  prefix: array<u32, 40>,
  suffix: array<u32, 40>,
}

struct Matches {
  counter: atomic<u32>,
  indices: array<u32, 1024>,
}

@group(0) @binding(0) var<storage, read> pubkeys_u32: array<u32>;
@group(0) @binding(1) var<storage, read> params: Params;
@group(0) @binding(2) var<storage, read_write> matches: Matches;

fn addr_byte_at(addrWords: ptr<function, array<u32, 5>>, byteIndex: u32) -> u32 {
  let w = (*addrWords)[byteIndex / 4u];
  let b = byteIndex % 4u;
  return (w >> (8u * b)) & 0xffu;
}

fn addr_nibble_at(addrWords: ptr<function, array<u32, 5>>, nibbleIndex: u32) -> u32 {
  let byteIndex = nibbleIndex / 2u;
  let byteVal = addr_byte_at(addrWords, byteIndex);
  if ((nibbleIndex & 1u) == 0u) { return (byteVal >> 4u) & 0xfu; }
  return byteVal & 0xfu;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  // Each pubkey is 64 bytes = 16 u32
  let base = i * 16u;

  var st: array<U64, 25>;
  for (var k: u32 = 0u; k < 25u; k = k + 1u) { st[k] = U64(0u, 0u); }

  // Absorb 64 bytes into lanes 0..7 (each lane = 2 u32)
  for (var lane: u32 = 0u; lane < 8u; lane = lane + 1u) {
    let lo = pubkeys_u32[base + lane * 2u + 0u];
    let hi = pubkeys_u32[base + lane * 2u + 1u];
    st[lane] = u64_xor(st[lane], U64(lo, hi));
  }

  // Pad: 0x01 at byte offset 64 (lane 8, byte 0), and 0x80 at last byte of block (lane 16, byte 7)
  st[8] = u64_xor(st[8], u64_from_u32(1u));
  st[16] = u64_xor(st[16], U64(0u, 0x80000000u));

  keccak_f1600(&st);

  // Keccak-256 digest: first 32 bytes of state (lanes 0..3)
  // Address bytes = digest[12..32): 20 bytes -> words:
  // w0 = lane1.hi, w1 = lane2.lo, w2 = lane2.hi, w3 = lane3.lo, w4 = lane3.hi
  var addrWords: array<u32, 5>;
  addrWords[0] = st[1].hi;
  addrWords[1] = st[2].lo;
  addrWords[2] = st[2].hi;
  addrWords[3] = st[3].lo;
  addrWords[4] = st[3].hi;

  // Compare prefix
  for (var p: u32 = 0u; p < params.prefixLen; p = p + 1u) {
    if (addr_nibble_at(&addrWords, p) != params.prefix[p]) { return; }
  }
  // Compare suffix
  let start = 40u - params.suffixLen;
  for (var q: u32 = 0u; q < params.suffixLen; q = q + 1u) {
    if (addr_nibble_at(&addrWords, start + q) != params.suffix[q]) { return; }
  }

  let slot = atomicAdd(&matches.counter, 1u);
  if (slot < MAX_MATCHES) {
    matches.indices[slot] = i;
  }
}



