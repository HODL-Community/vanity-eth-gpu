export const ADDRESS_NIBBLE_LENGTH = 40

export type MergedAddressPattern = {
  valid: boolean
  body: Array<string | null>
  constrainedNibbles: number
  constrainedLetters: number
  message?: string
}

function charsMatch(a: string, b: string, caseSensitive: boolean): boolean {
  return caseSensitive ? a === b : a.toLowerCase() === b.toLowerCase()
}

export function mergeAddressPattern(
  prefix: string,
  suffix: string,
  caseSensitive: boolean
): MergedAddressPattern {
  const body: Array<string | null> = Array.from({ length: ADDRESS_NIBBLE_LENGTH }, () => null)
  const normalizedPrefix = caseSensitive ? prefix : prefix.toLowerCase()
  const normalizedSuffix = caseSensitive ? suffix : suffix.toLowerCase()

  if (prefix.length > ADDRESS_NIBBLE_LENGTH || suffix.length > ADDRESS_NIBBLE_LENGTH) {
    return {
      valid: false,
      body,
      constrainedNibbles: 0,
      constrainedLetters: 0,
      message: 'Prefix and suffix must each be at most 40 hex characters.'
    }
  }

  for (let i = 0; i < normalizedPrefix.length; i++) {
    body[i] = normalizedPrefix[i]
  }

  const suffixStart = ADDRESS_NIBBLE_LENGTH - normalizedSuffix.length
  for (let i = 0; i < normalizedSuffix.length; i++) {
    const position = suffixStart + i
    const next = normalizedSuffix[i]
    const existing = body[position]

    if (existing !== null && !charsMatch(existing, next, caseSensitive)) {
      return {
        valid: false,
        body,
        constrainedNibbles: body.filter(Boolean).length,
        constrainedLetters: body.filter((ch): ch is string => ch !== null && /[a-fA-F]/.test(ch)).length,
        message: 'Prefix and suffix overlap with contradictory characters, so no address can match both.'
      }
    }

    body[position] = existing ?? next
  }

  const constrainedNibbles = body.filter((ch): ch is string => ch !== null).length
  const constrainedLetters = body.filter((ch): ch is string => ch !== null && /[a-fA-F]/.test(ch)).length

  return { valid: true, body, constrainedNibbles, constrainedLetters }
}

export function calculatePatternDifficulty(prefix: string, suffix: string, caseSensitive: boolean): number {
  const pattern = mergeAddressPattern(prefix, suffix, caseSensitive)
  if (!pattern.valid) return Infinity

  const base = 16 ** pattern.constrainedNibbles
  if (!caseSensitive) return base
  return base * (2 ** pattern.constrainedLetters)
}
