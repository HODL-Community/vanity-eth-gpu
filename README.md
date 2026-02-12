# Vanity SOL GPU

A fast Solana vanity address generator that runs entirely in your browser.

## Features

- **Multi-threaded** - Uses Web Workers for parallel keypair generation
- **GPU-accelerated matching** - Uses WebGPU to parallelize Base58 vanity matching when available
- **Privacy First** - All computations run locally in your browser, no server communication
- **Custom Prefix/Suffix** - Find addresses starting or ending with your desired Base58 characters
- **Wallet + Program ID Targets** - Scan either wallet addresses or program IDs
- **Keypair Export** - Download Solana-compatible keypair JSON files

## Requirements

- A modern browser (Chrome, Firefox, Edge, Safari)

## Usage

1. Choose target: wallet address or program ID
2. Enter your desired prefix and/or suffix (Base58 characters)
3. Click Generate and wait for a match
4. Once found, reveal the secret key or download keypair JSON

## Security

- Disconnect from the internet before generating for maximum security
- Never share your secret key
- Always verify the address matches your requirements before use

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build

# Run unit tests
npm run test:unit

# Run browser E2E tests
npm run test:e2e

# Run full quality gate (build + unit + e2e)
npm run check
```

## Testing

- Unit tests use `vitest` and cover core Base58/keys logic.
- E2E tests use `@playwright/test` and exercise real UI flows in Chromium.
- CI runs `build`, `test:unit`, and `test:e2e` on every push/PR.
- For deterministic test runs, the dev server is started with `VITE_FORCE_BACKEND=cpu`.

## Tech Stack

- TypeScript
- Vite
- Web Workers
- WebGPU
- @noble/curves (ed25519)

## Notes

- Runtime auto-benchmarks GPU hybrid mode vs CPU mode and picks the faster backend.
- If WebGPU is unavailable, the app falls back to CPU-only search.
- You can force a backend for troubleshooting with `VITE_FORCE_BACKEND=cpu` or `VITE_FORCE_BACKEND=gpu`.

## License

MIT
