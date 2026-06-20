// keystoreV3.ts uses window.crypto.getRandomValues / randomUUID. In Node (vitest
// 'node' env) there is no window — polyfill it from the global webcrypto.
import { webcrypto } from 'node:crypto'

if (typeof (globalThis as any).window === 'undefined') {
  ;(globalThis as any).window = { crypto: webcrypto }
}
