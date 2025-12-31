export function nowMs() {
  return (typeof performance !== 'undefined' ? performance.now() : Date.now())
}

export function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex
  if (s.length % 2 !== 0) throw new Error('Invalid hex length')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function hexToNibbles(hex: string): number[] {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex
  const out: number[] = []
  for (const ch of s) {
    const v = parseInt(ch, 16)
    if (Number.isNaN(v)) throw new Error(`Invalid hex char: ${ch}`)
    out.push(v)
  }
  return out
}

export function nibblesToLowerHex(nibbles: number[]): string {
  const hex = '0123456789abcdef'
  let out = ''
  for (const n of nibbles) out += hex[n & 0xf]
  return out
}



