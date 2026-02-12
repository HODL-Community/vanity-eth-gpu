const NO_MATCH: u32 = 0xffffffffu;

const ALPHABET: array<u32, 58> = array<u32, 58>(
  49u, 50u, 51u, 52u, 53u, 54u, 55u, 56u, 57u,
  65u, 66u, 67u, 68u, 69u, 70u, 71u, 72u, 74u, 75u, 76u, 77u, 78u, 80u, 81u,
  82u, 83u, 84u, 85u, 86u, 87u, 88u, 89u, 90u,
  97u, 98u, 99u, 100u, 101u, 102u, 103u, 104u, 105u, 106u, 107u, 109u, 110u,
  111u, 112u, 113u, 114u, 115u, 116u, 117u, 118u, 119u, 120u, 121u, 122u
);

struct Params {
  count: u32,
  prefixLen: u32,
  suffixLen: u32,
  caseSensitive: u32,
  prefix: array<u32, 44>,
  suffix: array<u32, 44>,
}

@group(0) @binding(0) var<storage, read> pubkeys: array<u32>;
@group(0) @binding(1) var<storage, read> params: Params;
@group(0) @binding(2) var<storage, read_write> matchIndex: atomic<u32>;

fn asciiLower(code: u32) -> u32 {
  if (code >= 65u && code <= 90u) {
    return code + 32u;
  }
  return code;
}

fn getPubByte(pubkeyIndex: u32, byteIndex: u32) -> u32 {
  let wordIndex = pubkeyIndex * 8u + (byteIndex / 4u);
  let shift = (byteIndex % 4u) * 8u;
  return (pubkeys[wordIndex] >> shift) & 255u;
}

fn keyMatches(pubkeyIndex: u32) -> bool {
  var digits: array<u32, 45>;
  var digitsLen: u32 = 1u;
  digits[0] = 0u;

  var leadingZeros: u32 = 0u;
  var allLeadingZeros = true;

  for (var i: u32 = 0u; i < 32u; i = i + 1u) {
    let byteVal = getPubByte(pubkeyIndex, i);

    if (allLeadingZeros && byteVal == 0u) {
      leadingZeros = leadingZeros + 1u;
    } else {
      allLeadingZeros = false;
    }

    var carry = byteVal;
    for (var j: u32 = 0u; j < digitsLen; j = j + 1u) {
      let value = digits[j] * 256u + carry;
      digits[j] = value % 58u;
      carry = value / 58u;
    }

    loop {
      if (carry == 0u) {
        break;
      }
      digits[digitsLen] = carry % 58u;
      digitsLen = digitsLen + 1u;
      carry = carry / 58u;
    }
  }

  for (var z: u32 = 0u; z < leadingZeros; z = z + 1u) {
    digits[digitsLen] = 0u;
    digitsLen = digitsLen + 1u;
  }

  let prefixLen = params.prefixLen;
  let suffixLen = params.suffixLen;

  if (prefixLen + suffixLen > digitsLen) {
    return false;
  }

  for (var p: u32 = 0u; p < prefixLen; p = p + 1u) {
    let digit = digits[digitsLen - 1u - p];
    var actual = ALPHABET[digit];
    var expected = params.prefix[p];

    if (params.caseSensitive == 0u) {
      actual = asciiLower(actual);
      expected = asciiLower(expected);
    }

    if (actual != expected) {
      return false;
    }
  }

  for (var s: u32 = 0u; s < suffixLen; s = s + 1u) {
    let digit = digits[suffixLen - 1u - s];
    var actual = ALPHABET[digit];
    var expected = params.suffix[s];

    if (params.caseSensitive == 0u) {
      actual = asciiLower(actual);
      expected = asciiLower(expected);
    }

    if (actual != expected) {
      return false;
    }
  }

  return true;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) globalId: vec3<u32>) {
  let idx = globalId.x;
  if (idx >= params.count) {
    return;
  }

  if (keyMatches(idx)) {
    atomicMin(&matchIndex, idx);
  }
}
