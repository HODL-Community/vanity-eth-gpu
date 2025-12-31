// Full GPU secp256k1 + Keccak-256 vanity address generator
// Simplified WGSL for maximum compatibility

// secp256k1 constants
const P0: u32 = 0xFFFFFC2Fu; const P1: u32 = 0xFFFFFFFEu; const P2: u32 = 0xFFFFFFFFu; const P3: u32 = 0xFFFFFFFFu;
const P4: u32 = 0xFFFFFFFFu; const P5: u32 = 0xFFFFFFFFu; const P6: u32 = 0xFFFFFFFFu; const P7: u32 = 0xFFFFFFFFu;

const GX0: u32 = 0x16F81798u; const GX1: u32 = 0x59F2815Bu; const GX2: u32 = 0x2DCE28D9u; const GX3: u32 = 0x029BFCDBu;
const GX4: u32 = 0xCE870B07u; const GX5: u32 = 0x55A06295u; const GX6: u32 = 0xF9DCBBACu; const GX7: u32 = 0x79BE667Eu;
const GY0: u32 = 0xFB10D4B8u; const GY1: u32 = 0x9C47D08Fu; const GY2: u32 = 0xA6855419u; const GY3: u32 = 0xFD17B448u;
const GY4: u32 = 0x0E1108A8u; const GY5: u32 = 0x5DA4FBFCu; const GY6: u32 = 0x26A3C465u; const GY7: u32 = 0x483ADA77u;

// Keccak constants
const RC_LO: array<u32, 24> = array<u32, 24>(
  0x00000001u, 0x00008082u, 0x0000808au, 0x80008000u, 0x0000808bu, 0x80000001u,
  0x80008081u, 0x00008009u, 0x0000008au, 0x00000088u, 0x80008009u, 0x8000000au,
  0x8000808bu, 0x0000008bu, 0x00008089u, 0x00008003u, 0x00008002u, 0x00000080u,
  0x0000800au, 0x8000000au, 0x80008081u, 0x00008080u, 0x80000001u, 0x80008008u
);
const RC_HI: array<u32, 24> = array<u32, 24>(
  0x00000000u, 0x00000000u, 0x80000000u, 0x80000000u, 0x00000000u, 0x00000000u,
  0x80000000u, 0x80000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
  0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u,
  0x00000000u, 0x80000000u, 0x80000000u, 0x80000000u, 0x00000000u, 0x80000000u
);

@group(0) @binding(0) var<storage, read> seeds: array<u32>;
@group(0) @binding(1) var<storage, read> params: array<u32>;
@group(0) @binding(2) var<storage, read_write> results: array<atomic<u32>>;

// Workgroup shared memory for intermediate results
var<private> rx: array<u32, 8>;
var<private> ry: array<u32, 8>;
var<private> rz: array<u32, 8>;
var<private> gx: array<u32, 8>;
var<private> gy: array<u32, 8>;
var<private> gz: array<u32, 8>;
var<private> tmp1: array<u32, 8>;
var<private> tmp2: array<u32, 8>;
var<private> tmp3: array<u32, 8>;
var<private> state: array<u32, 50>;

fn is_zero_8(a: ptr<private, array<u32, 8>>) -> bool {
  return (*a)[0] == 0u && (*a)[1] == 0u && (*a)[2] == 0u && (*a)[3] == 0u &&
         (*a)[4] == 0u && (*a)[5] == 0u && (*a)[6] == 0u && (*a)[7] == 0u;
}

fn copy_8(src: ptr<private, array<u32, 8>>, dst: ptr<private, array<u32, 8>>) {
  (*dst)[0] = (*src)[0]; (*dst)[1] = (*src)[1]; (*dst)[2] = (*src)[2]; (*dst)[3] = (*src)[3];
  (*dst)[4] = (*src)[4]; (*dst)[5] = (*src)[5]; (*dst)[6] = (*src)[6]; (*dst)[7] = (*src)[7];
}

fn set_one(a: ptr<private, array<u32, 8>>) {
  (*a)[0] = 1u; (*a)[1] = 0u; (*a)[2] = 0u; (*a)[3] = 0u;
  (*a)[4] = 0u; (*a)[5] = 0u; (*a)[6] = 0u; (*a)[7] = 0u;
}

fn set_zero(a: ptr<private, array<u32, 8>>) {
  (*a)[0] = 0u; (*a)[1] = 0u; (*a)[2] = 0u; (*a)[3] = 0u;
  (*a)[4] = 0u; (*a)[5] = 0u; (*a)[6] = 0u; (*a)[7] = 0u;
}

// 256-bit add, result in c
fn add256(a: ptr<private, array<u32, 8>>, b: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) -> u32 {
  var carry: u32 = 0u;
  for (var i: u32 = 0u; i < 8u; i = i + 1u) {
    let sum: u32 = (*a)[i] + (*b)[i] + carry;
    carry = select(0u, 1u, sum < (*a)[i] || (carry == 1u && sum <= (*a)[i]));
    (*c)[i] = sum;
  }
  return carry;
}

// 256-bit sub, result in c
fn sub256(a: ptr<private, array<u32, 8>>, b: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) -> u32 {
  var borrow: u32 = 0u;
  for (var i: u32 = 0u; i < 8u; i = i + 1u) {
    let bi: u32 = (*b)[i] + borrow;
    borrow = select(0u, 1u, (*a)[i] < bi || (borrow == 1u && (*b)[i] == 0xFFFFFFFFu));
    (*c)[i] = (*a)[i] - bi;
  }
  return borrow;
}

fn gte_p(a: ptr<private, array<u32, 8>>) -> bool {
  if ((*a)[7] > P7) { return true; } if ((*a)[7] < P7) { return false; }
  if ((*a)[6] > P6) { return true; } if ((*a)[6] < P6) { return false; }
  if ((*a)[5] > P5) { return true; } if ((*a)[5] < P5) { return false; }
  if ((*a)[4] > P4) { return true; } if ((*a)[4] < P4) { return false; }
  if ((*a)[3] > P3) { return true; } if ((*a)[3] < P3) { return false; }
  if ((*a)[2] > P2) { return true; } if ((*a)[2] < P2) { return false; }
  if ((*a)[1] > P1) { return true; } if ((*a)[1] < P1) { return false; }
  if ((*a)[0] >= P0) { return true; }
  return false;
}

fn sub_p(a: ptr<private, array<u32, 8>>) {
  var borrow: u32 = 0u;
  var t: u32;
  t = (*a)[0] - P0 - borrow; borrow = select(0u, 1u, (*a)[0] < P0 + borrow); (*a)[0] = t;
  t = (*a)[1] - P1 - borrow; borrow = select(0u, 1u, (*a)[1] < P1 + borrow); (*a)[1] = t;
  t = (*a)[2] - P2 - borrow; borrow = select(0u, 1u, (*a)[2] < P2 + borrow); (*a)[2] = t;
  t = (*a)[3] - P3 - borrow; borrow = select(0u, 1u, (*a)[3] < P3 + borrow); (*a)[3] = t;
  t = (*a)[4] - P4 - borrow; borrow = select(0u, 1u, (*a)[4] < P4 + borrow); (*a)[4] = t;
  t = (*a)[5] - P5 - borrow; borrow = select(0u, 1u, (*a)[5] < P5 + borrow); (*a)[5] = t;
  t = (*a)[6] - P6 - borrow; borrow = select(0u, 1u, (*a)[6] < P6 + borrow); (*a)[6] = t;
  t = (*a)[7] - P7 - borrow; (*a)[7] = t;
}

fn add_p(a: ptr<private, array<u32, 8>>) {
  var carry: u32 = 0u;
  var t: u32;
  t = (*a)[0] + P0 + carry; carry = select(0u, 1u, t < (*a)[0]); (*a)[0] = t;
  t = (*a)[1] + P1 + carry; carry = select(0u, 1u, t < (*a)[1]); (*a)[1] = t;
  t = (*a)[2] + P2 + carry; carry = select(0u, 1u, t < (*a)[2]); (*a)[2] = t;
  t = (*a)[3] + P3 + carry; carry = select(0u, 1u, t < (*a)[3]); (*a)[3] = t;
  t = (*a)[4] + P4 + carry; carry = select(0u, 1u, t < (*a)[4]); (*a)[4] = t;
  t = (*a)[5] + P5 + carry; carry = select(0u, 1u, t < (*a)[5]); (*a)[5] = t;
  t = (*a)[6] + P6 + carry; carry = select(0u, 1u, t < (*a)[6]); (*a)[6] = t;
  t = (*a)[7] + P7 + carry; (*a)[7] = t;
}

fn mod_add(a: ptr<private, array<u32, 8>>, b: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) {
  let carry = add256(a, b, c);
  if (carry == 1u || gte_p(c)) { sub_p(c); }
}

fn mod_sub(a: ptr<private, array<u32, 8>>, b: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) {
  let borrow = sub256(a, b, c);
  if (borrow == 1u) { add_p(c); }
}

fn mul32(a: u32, b: u32) -> vec2<u32> {
  let al = a & 0xFFFFu; let ah = a >> 16u;
  let bl = b & 0xFFFFu; let bh = b >> 16u;
  let p0 = al * bl; let p1 = al * bh; let p2 = ah * bl; let p3 = ah * bh;
  let mid = p1 + p2;
  let mid_c = select(0u, 0x10000u, mid < p1);
  let lo = p0 + (mid << 16u);
  let lo_c = select(0u, 1u, lo < p0);
  let hi = p3 + (mid >> 16u) + mid_c + lo_c;
  return vec2<u32>(lo, hi);
}

fn mod_mul(a: ptr<private, array<u32, 8>>, b: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) {
  var prod: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i = i + 1u) { prod[i] = 0u; }

  for (var i: u32 = 0u; i < 8u; i = i + 1u) {
    var carry: u32 = 0u;
    for (var j: u32 = 0u; j < 8u; j = j + 1u) {
      let m = mul32((*a)[i], (*b)[j]);
      var sum = prod[i + j] + m.x + carry;
      carry = select(0u, 1u, sum < prod[i + j]) + m.y;
      if (sum < m.x) { carry = carry + 1u; }
      prod[i + j] = sum;
    }
    prod[i + 8u] = carry;
  }

  // Reduction for secp256k1: multiply high part by (2^32 + 977) and add
  for (var i: u32 = 0u; i < 8u; i = i + 1u) { (*c)[i] = prod[i]; }

  for (var k: u32 = 0u; k < 8u; k = k + 1u) {
    let h = prod[8u + k];
    if (h == 0u) { continue; }

    // Add h * 977
    let m977 = mul32(h, 977u);
    var carry = m977.y;
    var sum = (*c)[k] + m977.x;
    carry = carry + select(0u, 1u, sum < (*c)[k]);
    (*c)[k] = sum;

    // Add h (for 2^32 factor) at position k+1
    if (k + 1u < 8u) {
      sum = (*c)[k + 1u] + h + carry;
      carry = select(0u, 1u, sum < (*c)[k + 1u]);
      (*c)[k + 1u] = sum;
    }

    // Propagate
    for (var j: u32 = k + 2u; j < 8u && carry > 0u; j = j + 1u) {
      sum = (*c)[j] + carry;
      carry = select(0u, 1u, sum < (*c)[j]);
      (*c)[j] = sum;
    }
  }

  if (gte_p(c)) { sub_p(c); }
}

fn mod_sqr(a: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) {
  mod_mul(a, a, c);
}

// Modular inverse via Fermat: a^(p-2) mod p
fn mod_inv(a: ptr<private, array<u32, 8>>, c: ptr<private, array<u32, 8>>) {
  // p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
  var result: array<u32, 8>;
  var base: array<u32, 8>;
  set_one(&result);
  copy_8(a, &base);

  // Exponent bits (p-2)
  let exp = array<u32, 8>(0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                          0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu);

  for (var i: u32 = 0u; i < 256u; i = i + 1u) {
    let limb = i / 32u;
    let bit = i % 32u;
    if ((exp[limb] & (1u << bit)) != 0u) {
      mod_mul(&result, &base, &tmp1);
      copy_8(&tmp1, &result);
    }
    mod_sqr(&base, &tmp1);
    copy_8(&tmp1, &base);
  }
  copy_8(&result, c);
}

fn init_G() {
  gx[0] = GX0; gx[1] = GX1; gx[2] = GX2; gx[3] = GX3;
  gx[4] = GX4; gx[5] = GX5; gx[6] = GX6; gx[7] = GX7;
  gy[0] = GY0; gy[1] = GY1; gy[2] = GY2; gy[3] = GY3;
  gy[4] = GY4; gy[5] = GY5; gy[6] = GY6; gy[7] = GY7;
  set_one(&gz);
}

// Point doubling in Jacobian coordinates
fn point_double_g() {
  if (is_zero_8(&gz)) { return; }

  var xx: array<u32, 8>; mod_sqr(&gx, &xx);
  var yy: array<u32, 8>; mod_sqr(&gy, &yy);
  var yyyy: array<u32, 8>; mod_sqr(&yy, &yyyy);

  var s: array<u32, 8>;
  mod_add(&gx, &yy, &tmp1);
  mod_sqr(&tmp1, &tmp2);
  mod_sub(&tmp2, &xx, &tmp1);
  mod_sub(&tmp1, &yyyy, &tmp2);
  mod_add(&tmp2, &tmp2, &s);

  var m: array<u32, 8>;
  mod_add(&xx, &xx, &tmp1);
  mod_add(&tmp1, &xx, &m);

  mod_sqr(&m, &tmp1);
  mod_add(&s, &s, &tmp2);
  mod_sub(&tmp1, &tmp2, &gx);

  mod_sub(&s, &gx, &tmp1);
  mod_mul(&m, &tmp1, &tmp2);
  mod_add(&yyyy, &yyyy, &tmp1);
  mod_add(&tmp1, &tmp1, &tmp3);
  mod_add(&tmp3, &tmp3, &tmp1);
  mod_sub(&tmp2, &tmp1, &gy);

  mod_mul(&gy, &gz, &tmp1);
  mod_add(&tmp1, &tmp1, &gz);
}

// Point addition R = R + G (Jacobian)
fn point_add_rg() {
  if (is_zero_8(&rz)) {
    copy_8(&gx, &rx); copy_8(&gy, &ry); copy_8(&gz, &rz);
    return;
  }
  if (is_zero_8(&gz)) { return; }

  var z1z1: array<u32, 8>; mod_sqr(&rz, &z1z1);
  var z2z2: array<u32, 8>; mod_sqr(&gz, &z2z2);
  var u1: array<u32, 8>; mod_mul(&rx, &z2z2, &u1);
  var u2: array<u32, 8>; mod_mul(&gx, &z1z1, &u2);

  var s1: array<u32, 8>;
  mod_mul(&gz, &z2z2, &tmp1);
  mod_mul(&ry, &tmp1, &s1);

  var s2: array<u32, 8>;
  mod_mul(&rz, &z1z1, &tmp1);
  mod_mul(&gy, &tmp1, &s2);

  var h: array<u32, 8>; mod_sub(&u2, &u1, &h);
  var r: array<u32, 8>; mod_sub(&s2, &s1, &r);

  var hh: array<u32, 8>; mod_sqr(&h, &hh);
  var hhh: array<u32, 8>; mod_mul(&h, &hh, &hhh);
  var u1hh: array<u32, 8>; mod_mul(&u1, &hh, &u1hh);

  mod_sqr(&r, &tmp1);
  mod_add(&u1hh, &u1hh, &tmp2);
  mod_add(&hhh, &tmp2, &tmp3);
  mod_sub(&tmp1, &tmp3, &rx);

  mod_sub(&u1hh, &rx, &tmp1);
  mod_mul(&r, &tmp1, &tmp2);
  mod_mul(&s1, &hhh, &tmp1);
  mod_sub(&tmp2, &tmp1, &ry);

  mod_mul(&rz, &gz, &tmp1);
  mod_mul(&tmp1, &h, &rz);
}

// Scalar multiplication k*G
fn scalar_mult(k: ptr<private, array<u32, 8>>) {
  set_zero(&rx); set_zero(&ry); set_zero(&rz);
  init_G();

  for (var i: u32 = 0u; i < 256u; i = i + 1u) {
    let limb = i / 32u;
    let bit = i % 32u;
    if (((*k)[limb] & (1u << bit)) != 0u) {
      point_add_rg();
    }
    point_double_g();
  }
}

// Convert to affine
fn to_affine(ax: ptr<private, array<u32, 8>>, ay: ptr<private, array<u32, 8>>) {
  if (is_zero_8(&rz)) {
    set_zero(ax); set_zero(ay);
    return;
  }
  var zinv: array<u32, 8>; mod_inv(&rz, &zinv);
  var zinv2: array<u32, 8>; mod_sqr(&zinv, &zinv2);
  var zinv3: array<u32, 8>; mod_mul(&zinv2, &zinv, &zinv3);
  mod_mul(&rx, &zinv2, ax);
  mod_mul(&ry, &zinv3, ay);
}

// Keccak-256
fn rotl64(lo: u32, hi: u32, n: u32) -> vec2<u32> {
  if (n == 0u) { return vec2<u32>(lo, hi); }
  if (n < 32u) {
    return vec2<u32>((lo << n) | (hi >> (32u - n)), (hi << n) | (lo >> (32u - n)));
  }
  let m = n - 32u;
  return vec2<u32>((hi << m) | (lo >> (32u - m)), (lo << m) | (hi >> (32u - m)));
}

fn keccak256(pubkey: ptr<private, array<u32, 16>>) {
  for (var i: u32 = 0u; i < 50u; i = i + 1u) { state[i] = 0u; }
  for (var i: u32 = 0u; i < 16u; i = i + 1u) { state[i] = (*pubkey)[i]; }
  state[16u] = state[16u] ^ 0x01u;
  state[33u] = state[33u] ^ 0x80000000u;

  let PILN = array<u32, 24>(10u,7u,11u,17u,18u,3u,5u,16u,8u,21u,24u,4u,15u,23u,19u,13u,12u,2u,20u,14u,22u,9u,6u,1u);
  let ROTC = array<u32, 24>(1u,3u,6u,10u,15u,21u,28u,36u,45u,55u,2u,14u,27u,41u,56u,8u,25u,43u,62u,18u,39u,61u,20u,44u);

  for (var round: u32 = 0u; round < 24u; round = round + 1u) {
    var c: array<u32, 10>;
    for (var x: u32 = 0u; x < 5u; x = x + 1u) {
      c[x*2u] = state[x*2u] ^ state[10u+x*2u] ^ state[20u+x*2u] ^ state[30u+x*2u] ^ state[40u+x*2u];
      c[x*2u+1u] = state[x*2u+1u] ^ state[10u+x*2u+1u] ^ state[20u+x*2u+1u] ^ state[30u+x*2u+1u] ^ state[40u+x*2u+1u];
    }

    for (var x: u32 = 0u; x < 5u; x = x + 1u) {
      let x1 = (x + 1u) % 5u;
      let x4 = (x + 4u) % 5u;
      let rot = rotl64(c[x1*2u], c[x1*2u+1u], 1u);
      let d0 = c[x4*2u] ^ rot.x;
      let d1 = c[x4*2u+1u] ^ rot.y;
      for (var y: u32 = 0u; y < 5u; y = y + 1u) {
        let idx = (y * 5u + x) * 2u;
        state[idx] = state[idx] ^ d0;
        state[idx+1u] = state[idx+1u] ^ d1;
      }
    }

    var temp: array<u32, 50>;
    temp[0] = state[0]; temp[1] = state[1];
    var t0 = state[2]; var t1 = state[3];
    for (var i: u32 = 0u; i < 24u; i = i + 1u) {
      let j = PILN[i];
      let n0 = state[j * 2u]; let n1 = state[j * 2u + 1u];
      let rot = rotl64(t0, t1, ROTC[i]);
      temp[j * 2u] = rot.x; temp[j * 2u + 1u] = rot.y;
      t0 = n0; t1 = n1;
    }

    for (var y: u32 = 0u; y < 5u; y = y + 1u) {
      for (var x: u32 = 0u; x < 5u; x = x + 1u) {
        let i0 = (y * 5u + x) * 2u;
        let i1 = (y * 5u + ((x + 1u) % 5u)) * 2u;
        let i2 = (y * 5u + ((x + 2u) % 5u)) * 2u;
        state[i0] = temp[i0] ^ ((~temp[i1]) & temp[i2]);
        state[i0+1u] = temp[i0+1u] ^ ((~temp[i1+1u]) & temp[i2+1u]);
      }
    }

    state[0] = state[0] ^ RC_LO[round];
    state[1] = state[1] ^ RC_HI[round];
  }
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let idx = gid.x;
  let batch_size = params[0];
  if (idx >= batch_size) { return; }

  let prefix_len = params[1];
  let suffix_len = params[2];

  var privkey: array<u32, 8>;
  let seed_base = idx * 8u;
  for (var i: u32 = 0u; i < 8u; i = i + 1u) {
    privkey[i] = seeds[seed_base + i] ^ (idx * 2654435761u + i * 1597334677u);
  }

  scalar_mult(&privkey);

  var ax: array<u32, 8>;
  var ay: array<u32, 8>;
  to_affine(&ax, &ay);

  // Pack pubkey in big-endian format (Ethereum requires big-endian)
  // ax/ay are in little-endian limb order, need to reverse both limb and byte order
  var pubkey: array<u32, 16>;
  for (var i: u32 = 0u; i < 8u; i = i + 1u) {
    // Reverse limb order (7-i) and byte swap within each u32
    let vx = ax[7u - i];
    let vy = ay[7u - i];
    // Byte swap: ABCD -> DCBA
    pubkey[i] = ((vx & 0xFFu) << 24u) | ((vx & 0xFF00u) << 8u) | ((vx >> 8u) & 0xFF00u) | ((vx >> 24u) & 0xFFu);
    pubkey[8u + i] = ((vy & 0xFFu) << 24u) | ((vy & 0xFF00u) << 8u) | ((vy >> 8u) & 0xFF00u) | ((vy >> 24u) & 0xFFu);
  }

  keccak256(&pubkey);

  var match_ok = true;
  for (var i: u32 = 0u; i < prefix_len; i = i + 1u) {
    if (!match_ok) { break; }
    let byte_idx = 12u + i / 2u;
    let word_idx = byte_idx / 4u;
    let byte_in_word = byte_idx % 4u;
    let byte_val = (state[word_idx] >> (byte_in_word * 8u)) & 0xFFu;
    let nibble = select(byte_val >> 4u, byte_val & 0xFu, i % 2u == 1u);
    if (nibble != params[4u + i]) { match_ok = false; }
  }

  for (var i: u32 = 0u; i < suffix_len; i = i + 1u) {
    if (!match_ok) { break; }
    let addr_nibble = 39u - (suffix_len - 1u - i);
    let byte_idx = 12u + addr_nibble / 2u;
    let word_idx = byte_idx / 4u;
    let byte_in_word = byte_idx % 4u;
    let byte_val = (state[word_idx] >> (byte_in_word * 8u)) & 0xFFu;
    let nibble = select(byte_val >> 4u, byte_val & 0xFu, addr_nibble % 2u == 1u);
    if (nibble != params[44u + i]) { match_ok = false; }
  }

  if (match_ok) {
    let slot = atomicAdd(&results[0], 1u);
    if (slot < 16u) {
      let base = 1u + slot * 17u;
      for (var i: u32 = 0u; i < 8u; i = i + 1u) {
        atomicStore(&results[base + i], privkey[i]);
        atomicStore(&results[base + 8u + i], state[i]);
      }
      atomicStore(&results[base + 16u], idx);
    }
  }
}
