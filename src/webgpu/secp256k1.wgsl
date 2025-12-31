// Full secp256k1 + Keccak-256 vanity address generation on GPU
// 256-bit integers represented as 8 x u32 (little-endian limbs)

struct U256 {
  limbs: array<u32, 8>
}

struct Point {
  x: U256,
  y: U256,
  z: U256  // Jacobian coordinates for faster arithmetic
}

// secp256k1 prime: p = 2^256 - 2^32 - 977
const P: array<u32, 8> = array<u32, 8>(
  0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
  0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
);

// Generator point G (x coordinate)
const GX: array<u32, 8> = array<u32, 8>(
  0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDB,
  0xCE870B07u, 0x55A06295u, 0xF9DCBBAC, 0x79BE667E
);

// Generator point G (y coordinate)
const GY: array<u32, 8> = array<u32, 8>(
  0xFB10D4B8u, 0x9C47D08Fu, 0xA6855419u, 0xFD17B448,
  0x0E1108A8u, 0x5DA4FBFC, 0x26A3C465u, 0x483ADA77
);

// Keccak-256 round constants
const RC: array<u32, 48> = array<u32, 48>(
  0x00000001u, 0x00000000u, 0x00008082u, 0x00000000u,
  0x0000808au, 0x80000000u, 0x80008000u, 0x80000000u,
  0x0000808bu, 0x00000000u, 0x80000001u, 0x00000000u,
  0x80008081u, 0x80000000u, 0x00008009u, 0x80000000u,
  0x0000008au, 0x00000000u, 0x00000088u, 0x00000000u,
  0x80008009u, 0x00000000u, 0x8000000au, 0x00000000u,
  0x8000808bu, 0x80000000u, 0x0000008bu, 0x80000000u,
  0x00008089u, 0x80000000u, 0x00008003u, 0x80000000u,
  0x00008002u, 0x80000000u, 0x00000080u, 0x80000000u,
  0x0000800au, 0x00000000u, 0x8000000au, 0x80000000u,
  0x80008081u, 0x80000000u, 0x00008080u, 0x80000000u,
  0x80000001u, 0x00000000u, 0x80008008u, 0x80000000u
);

// Rotation offsets for Keccak
const ROTC: array<u32, 24> = array<u32, 24>(
  1u, 3u, 6u, 10u, 15u, 21u, 28u, 36u, 45u, 55u, 2u, 14u,
  27u, 41u, 56u, 8u, 25u, 43u, 62u, 18u, 39u, 61u, 20u, 44u
);

const PILN: array<u32, 24> = array<u32, 24>(
  10u, 7u, 11u, 17u, 18u, 3u, 5u, 16u, 8u, 21u, 24u, 4u,
  15u, 23u, 19u, 13u, 12u, 2u, 20u, 14u, 22u, 9u, 6u, 1u
);

// Buffers
@group(0) @binding(0) var<storage, read> seeds: array<u32>;
@group(0) @binding(1) var<storage, read> params: array<u32>;
@group(0) @binding(2) var<storage, read_write> results: array<u32>;

// ============ 256-bit arithmetic ============

fn u256_zero() -> U256 {
  return U256(array<u32, 8>(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
}

fn u256_one() -> U256 {
  return U256(array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u));
}

fn u256_from_array(a: array<u32, 8>) -> U256 {
  return U256(a);
}

fn u256_eq(a: U256, b: U256) -> bool {
  for (var i = 0u; i < 8u; i++) {
    if (a.limbs[i] != b.limbs[i]) { return false; }
  }
  return true;
}

fn u256_is_zero(a: U256) -> bool {
  for (var i = 0u; i < 8u; i++) {
    if (a.limbs[i] != 0u) { return false; }
  }
  return true;
}

fn u256_gte(a: U256, b: U256) -> bool {
  for (var i = 7i; i >= 0i; i--) {
    if (a.limbs[i] > b.limbs[i]) { return true; }
    if (a.limbs[i] < b.limbs[i]) { return false; }
  }
  return true; // equal
}

fn u256_add(a: U256, b: U256) -> U256 {
  var result: U256;
  var carry = 0u;
  for (var i = 0u; i < 8u; i++) {
    let sum = u64(a.limbs[i]) + u64(b.limbs[i]) + u64(carry);
    result.limbs[i] = u32(sum & 0xFFFFFFFFu);
    carry = u32(sum >> 32u);
  }
  return result;
}

fn u256_sub(a: U256, b: U256) -> U256 {
  var result: U256;
  var borrow = 0u;
  for (var i = 0u; i < 8u; i++) {
    let diff = u64(a.limbs[i]) - u64(b.limbs[i]) - u64(borrow);
    result.limbs[i] = u32(diff & 0xFFFFFFFFu);
    borrow = select(0u, 1u, diff > 0xFFFFFFFFu);
  }
  return result;
}

fn u256_mod_p(a: U256) -> U256 {
  let p = u256_from_array(P);
  var r = a;
  while (u256_gte(r, p)) {
    r = u256_sub(r, p);
  }
  return r;
}

// Montgomery-style multiplication mod p (simplified)
fn u256_mul_mod(a: U256, b: U256) -> U256 {
  // Full 512-bit product then reduce
  var product: array<u32, 16>;
  for (var i = 0u; i < 16u; i++) { product[i] = 0u; }

  for (var i = 0u; i < 8u; i++) {
    var carry = 0u;
    for (var j = 0u; j < 8u; j++) {
      let mul = u64(a.limbs[i]) * u64(b.limbs[j]) + u64(product[i + j]) + u64(carry);
      product[i + j] = u32(mul & 0xFFFFFFFFu);
      carry = u32(mul >> 32u);
    }
    product[i + 8u] = carry;
  }

  // Barrett reduction for secp256k1 prime
  // p = 2^256 - 2^32 - 977, so reduction is efficient
  var result: U256;
  for (var i = 0u; i < 8u; i++) {
    result.limbs[i] = product[i];
  }

  // Reduce high bits
  for (var i = 8u; i < 16u; i++) {
    if (product[i] == 0u) { continue; }
    let hi = product[i];
    // Multiply hi by (2^32 + 977) and add to result at position i-8
    let pos = i - 8u;
    var carry = 0u;

    // Add hi * 977
    let mul977 = u64(hi) * 977u + u64(result.limbs[pos]) + u64(carry);
    result.limbs[pos] = u32(mul977 & 0xFFFFFFFFu);
    carry = u32(mul977 >> 32u);

    // Add hi * 2^32 (just add hi at next position)
    if (pos + 1u < 8u) {
      let sum = u64(result.limbs[pos + 1u]) + u64(hi) + u64(carry);
      result.limbs[pos + 1u] = u32(sum & 0xFFFFFFFFu);
      carry = u32(sum >> 32u);
    }

    // Propagate carry
    for (var k = pos + 2u; k < 8u && carry > 0u; k++) {
      let sum = u64(result.limbs[k]) + u64(carry);
      result.limbs[k] = u32(sum & 0xFFFFFFFFu);
      carry = u32(sum >> 32u);
    }
  }

  return u256_mod_p(result);
}

fn u256_square_mod(a: U256) -> U256 {
  return u256_mul_mod(a, a);
}

// Modular inverse using Fermat's little theorem: a^(p-2) mod p
fn u256_inv_mod(a: U256) -> U256 {
  // p-2 for secp256k1
  let p_minus_2 = U256(array<u32, 8>(
    0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
  ));

  var result = u256_one();
  var base = a;
  var exp = p_minus_2;

  for (var i = 0u; i < 256u; i++) {
    let limb_idx = i / 32u;
    let bit_idx = i % 32u;
    if ((exp.limbs[limb_idx] & (1u << bit_idx)) != 0u) {
      result = u256_mul_mod(result, base);
    }
    base = u256_square_mod(base);
  }

  return result;
}

// ============ Point arithmetic (Jacobian coordinates) ============

fn point_double(p: Point) -> Point {
  if (u256_is_zero(p.y)) {
    return Point(u256_zero(), u256_zero(), u256_zero());
  }

  let xx = u256_square_mod(p.x);
  let yy = u256_square_mod(p.y);
  let yyyy = u256_square_mod(yy);
  let zz = u256_square_mod(p.z);

  // S = 2 * ((X + YY)^2 - XX - YYYY)
  let x_plus_yy = u256_mod_p(u256_add(p.x, yy));
  var s = u256_square_mod(x_plus_yy);
  s = u256_mod_p(u256_sub(u256_mod_p(u256_sub(s, xx)), yyyy));
  s = u256_mod_p(u256_add(s, s));

  // M = 3 * XX (a=0 for secp256k1)
  var m = u256_mod_p(u256_add(xx, u256_add(xx, xx)));

  // X3 = M^2 - 2*S
  let mm = u256_square_mod(m);
  let s2 = u256_mod_p(u256_add(s, s));
  let x3 = u256_mod_p(u256_sub(mm, s2));

  // Y3 = M * (S - X3) - 8*YYYY
  let y3_part = u256_mul_mod(m, u256_mod_p(u256_sub(s, x3)));
  var yyyy8 = yyyy;
  for (var i = 0u; i < 3u; i++) {
    yyyy8 = u256_mod_p(u256_add(yyyy8, yyyy8));
  }
  let y3 = u256_mod_p(u256_sub(y3_part, yyyy8));

  // Z3 = 2 * Y * Z
  let z3 = u256_mul_mod(p.y, p.z);
  let z3_final = u256_mod_p(u256_add(z3, z3));

  return Point(x3, y3, z3_final);
}

fn point_add(p1: Point, p2: Point) -> Point {
  if (u256_is_zero(p1.z)) { return p2; }
  if (u256_is_zero(p2.z)) { return p1; }

  let z1z1 = u256_square_mod(p1.z);
  let z2z2 = u256_square_mod(p2.z);
  let u1 = u256_mul_mod(p1.x, z2z2);
  let u2 = u256_mul_mod(p2.x, z1z1);
  let s1 = u256_mul_mod(p1.y, u256_mul_mod(p2.z, z2z2));
  let s2 = u256_mul_mod(p2.y, u256_mul_mod(p1.z, z1z1));

  if (u256_eq(u1, u2)) {
    if (u256_eq(s1, s2)) {
      return point_double(p1);
    }
    return Point(u256_zero(), u256_zero(), u256_zero()); // infinity
  }

  let h = u256_mod_p(u256_sub(u2, u1));
  let h2 = u256_square_mod(h);
  let h3 = u256_mul_mod(h, h2);
  let r = u256_mod_p(u256_sub(s2, s1));

  let x3_part = u256_square_mod(r);
  let u1h2 = u256_mul_mod(u1, h2);
  let u1h2_2 = u256_mod_p(u256_add(u1h2, u1h2));
  let x3 = u256_mod_p(u256_sub(u256_mod_p(u256_sub(x3_part, h3)), u1h2_2));

  let y3 = u256_mod_p(u256_sub(u256_mul_mod(r, u256_mod_p(u256_sub(u1h2, x3))), u256_mul_mod(s1, h3)));
  let z3 = u256_mul_mod(h, u256_mul_mod(p1.z, p2.z));

  return Point(x3, y3, z3);
}

// Scalar multiplication: k * G
fn scalar_mult(k: U256) -> Point {
  let g = Point(
    u256_from_array(GX),
    u256_from_array(GY),
    u256_one()
  );

  var result = Point(u256_zero(), u256_zero(), u256_zero());
  var addend = g;

  for (var i = 0u; i < 256u; i++) {
    let limb_idx = i / 32u;
    let bit_idx = i % 32u;
    if ((k.limbs[limb_idx] & (1u << bit_idx)) != 0u) {
      result = point_add(result, addend);
    }
    addend = point_double(addend);
  }

  return result;
}

// Convert Jacobian to affine coordinates
fn to_affine(p: Point) -> array<U256, 2> {
  if (u256_is_zero(p.z)) {
    return array<U256, 2>(u256_zero(), u256_zero());
  }

  let z_inv = u256_inv_mod(p.z);
  let z_inv2 = u256_square_mod(z_inv);
  let z_inv3 = u256_mul_mod(z_inv2, z_inv);

  let x = u256_mul_mod(p.x, z_inv2);
  let y = u256_mul_mod(p.y, z_inv3);

  return array<U256, 2>(x, y);
}

// ============ Keccak-256 ============

fn rotl64(lo: u32, hi: u32, n: u32) -> array<u32, 2> {
  if (n == 0u) { return array<u32, 2>(lo, hi); }
  if (n < 32u) {
    return array<u32, 2>(
      (lo << n) | (hi >> (32u - n)),
      (hi << n) | (lo >> (32u - n))
    );
  }
  let m = n - 32u;
  return array<u32, 2>(
    (hi << m) | (lo >> (32u - m)),
    (lo << m) | (hi >> (32u - m))
  );
}

fn keccak256(data: array<u32, 16>) -> array<u32, 8> {
  // State: 25 lanes of 64 bits = 50 u32s
  var state: array<u32, 50>;
  for (var i = 0u; i < 50u; i++) { state[i] = 0u; }

  // Absorb 64 bytes (512 bits) - our pubkey
  for (var i = 0u; i < 16u; i++) {
    state[i] = data[i];
  }

  // Padding for 64-byte input with rate=136 bytes (1088 bits)
  state[16] ^= 0x01u;  // Start of padding
  state[33] ^= 0x80000000u;  // End of padding at byte 135

  // Keccak-f[1600] - 24 rounds
  for (var round = 0u; round < 24u; round++) {
    // Theta
    var c: array<u32, 10>;
    for (var x = 0u; x < 5u; x++) {
      c[x * 2u] = state[x * 2u] ^ state[10u + x * 2u] ^ state[20u + x * 2u] ^ state[30u + x * 2u] ^ state[40u + x * 2u];
      c[x * 2u + 1u] = state[x * 2u + 1u] ^ state[10u + x * 2u + 1u] ^ state[20u + x * 2u + 1u] ^ state[30u + x * 2u + 1u] ^ state[40u + x * 2u + 1u];
    }

    for (var x = 0u; x < 5u; x++) {
      let rot = rotl64(c[((x + 1u) % 5u) * 2u], c[((x + 1u) % 5u) * 2u + 1u], 1u);
      let d_lo = c[((x + 4u) % 5u) * 2u] ^ rot[0];
      let d_hi = c[((x + 4u) % 5u) * 2u + 1u] ^ rot[1];
      for (var y = 0u; y < 5u; y++) {
        state[(y * 5u + x) * 2u] ^= d_lo;
        state[(y * 5u + x) * 2u + 1u] ^= d_hi;
      }
    }

    // Rho and Pi
    var temp: array<u32, 50>;
    temp[0] = state[0];
    temp[1] = state[1];
    for (var i = 0u; i < 24u; i++) {
      let j = PILN[i];
      let rot = rotl64(state[j * 2u], state[j * 2u + 1u], ROTC[i]);
      temp[j * 2u] = rot[0];
      temp[j * 2u + 1u] = rot[1];
    }

    // Chi
    for (var y = 0u; y < 5u; y++) {
      for (var x = 0u; x < 5u; x++) {
        let idx = (y * 5u + x) * 2u;
        let idx1 = (y * 5u + ((x + 1u) % 5u)) * 2u;
        let idx2 = (y * 5u + ((x + 2u) % 5u)) * 2u;
        state[idx] = temp[idx] ^ ((~temp[idx1]) & temp[idx2]);
        state[idx + 1u] = temp[idx + 1u] ^ ((~temp[idx1 + 1u]) & temp[idx2 + 1u]);
      }
    }

    // Iota
    state[0] ^= RC[round * 2u];
    state[1] ^= RC[round * 2u + 1u];
  }

  // Extract first 256 bits (8 u32s)
  var hash: array<u32, 8>;
  for (var i = 0u; i < 8u; i++) {
    hash[i] = state[i];
  }
  return hash;
}

// ============ Main compute shader ============

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let idx = gid.x;
  let batch_size = params[0];
  if (idx >= batch_size) { return; }

  let prefix_len = params[1];
  let suffix_len = params[2];

  // Generate private key from seed (PCG-style PRNG)
  var priv: U256;
  let seed_base = idx * 8u;
  for (var i = 0u; i < 8u; i++) {
    // Mix seed with index for uniqueness
    let s = seeds[seed_base + i];
    priv.limbs[i] = s ^ (idx * 2654435761u + i * 1597334677u);
  }

  // Compute public key
  let pub_jacobian = scalar_mult(priv);
  let pub_affine = to_affine(pub_jacobian);

  // Pack pubkey into 64 bytes (16 u32s) for Keccak
  var pubkey_data: array<u32, 16>;
  for (var i = 0u; i < 8u; i++) {
    pubkey_data[i] = pub_affine[0].limbs[i];      // X coordinate
    pubkey_data[8u + i] = pub_affine[1].limbs[i]; // Y coordinate
  }

  // Keccak-256 hash
  let hash = keccak256(pubkey_data);

  // Address is last 20 bytes of hash (last 5 u32s, but we need bytes 12-31)
  // In little-endian: hash[3] contains bytes 12-15, hash[4] bytes 16-19, etc.

  // Check prefix (from byte 12, nibble 0)
  var prefix_match = true;
  for (var i = 0u; i < prefix_len && prefix_match; i++) {
    let byte_idx = 12u + i / 2u;
    let word_idx = byte_idx / 4u;
    let word_byte = byte_idx % 4u;
    let byte_val = (hash[word_idx] >> (word_byte * 8u)) & 0xFFu;
    let nibble = select(byte_val >> 4u, byte_val & 0xFu, i % 2u == 1u);
    let expected = params[4u + i];
    if (nibble != expected) { prefix_match = false; }
  }

  // Check suffix (last nibbles of address)
  var suffix_match = true;
  for (var i = 0u; i < suffix_len && suffix_match; i++) {
    let nibble_from_end = suffix_len - 1u - i;
    let addr_nibble_idx = 39u - nibble_from_end;
    let byte_idx = 12u + addr_nibble_idx / 2u;
    let word_idx = byte_idx / 4u;
    let word_byte = byte_idx % 4u;
    let byte_val = (hash[word_idx] >> (word_byte * 8u)) & 0xFFu;
    let nibble = select(byte_val >> 4u, byte_val & 0xFu, addr_nibble_idx % 2u == 1u);
    let expected = params[44u + i];
    if (nibble != expected) { suffix_match = false; }
  }

  if (prefix_match && suffix_match) {
    // Atomically store result
    let slot = atomicAdd(&results[0], 1u);
    if (slot < 16u) {  // Max 16 results per batch
      let base = 1u + slot * 17u;  // 1 counter + 17 words per result (8 priv + 8 hash + 1 idx)
      for (var i = 0u; i < 8u; i++) {
        results[base + i] = priv.limbs[i];
      }
      for (var i = 0u; i < 8u; i++) {
        results[base + 8u + i] = hash[i];
      }
      results[base + 16u] = idx;
    }
  }
}
