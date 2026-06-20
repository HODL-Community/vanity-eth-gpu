export function nowMs() {
  return (typeof performance !== 'undefined' ? performance.now() : Date.now())
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
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error('Invalid hex characters')
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




