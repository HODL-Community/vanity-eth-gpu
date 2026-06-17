# Vanity ETH GPU

A fast Ethereum vanity address generator that runs entirely in your browser.

## Features

- **Multi-threaded** - Uses Web Workers for parallel address generation
- **Privacy First** - All computations run locally in your browser, no server communication
- **Custom Prefix/Suffix** - Find addresses starting or ending with your desired characters
- **Wallet + First Contract Targets** - Scan either the wallet address or its first `CREATE` deploy address (nonce 0)
- **Hybrid Backend** - GPU mode can run CPU workers in parallel for higher total throughput
- **Keystore Export** - Download encrypted keystore JSON files

## Requirements

- A modern browser (Chrome, Firefox, Edge, Safari)

## Usage

1. Choose target: wallet address or first contract address.
2. Enter your desired prefix and/or suffix (hex characters: 0-9, a-f).
3. Click Generate and wait for a match.
4. Confirm the result shows the local verification badge.
5. Reveal the private key or download an encrypted keystore.

## Contract target caveat

The contract target is specifically the first `CREATE` deployment address at nonce 0 for the generated deployer wallet. If that wallet sends any other transaction first, the first-contract address changes.

## Security

- All scanning runs locally in your browser.
- Disconnect from the internet after the page loads for maximum security.
- Never share your private key.
- The UI re-derives the wallet/target address from the private key before display/export.
- Impossible or contradictory prefix/suffix combinations are blocked before generation starts.

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Run tests
npm test

# Build for production
npm run build

# Check dependency audit
npm audit
```

## Tech Stack

- TypeScript
- Vite
- Web Workers
- @noble/secp256k1 for cryptography

## License

MIT
