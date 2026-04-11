# VSSS-WASM

Verifiable Shamir Secret Sharing over WASM for Node.js

## Description

Porting publicly verifiable shamir secret sharing from Rust to WASM for javascript.

**Features:**

- ✅ **Variable secret sizes** - Support secrets from 1 byte to hundreds of bytes
- ✅ **Cryptographic security** - Uses XChaCha20-Poly1305 encryption
- ✅ **Integrity verification** - SHA-256 hash verification on reconstruction
- **Secret size**: Any size (1+ bytes)
- **Share size**: 66 bytes each (1 byte length + 32 bytes identifier + 1 byte length + 32 bytes value)
- **Total shares**: 5
- **Threshold**: 3 (minimum shares needed to reconstruct)

## Installation

```bash
npm install vsss-wasm
```

## Usage

```javascript
import { generatesecret, splitsecret, combinesecret } from "vsss-wasm";

// Generate a random 32-byte secret
const secret = generatesecret();

// Split any size secret into shares
const splitData = splitsecret(secret);

// Reconstruct secret from full split data
const combinedSecret = combinesecret(splitData);
```

**Example with custom secret:**

```javascript
// Split a 256-byte secret
const mySecret = new Uint8Array(256);
// ... fill with your data ...

const splitData = splitsecret(mySecret);
// Store shares on different systems, keep splitData safe

// Later, reconstruct
const reconstructed = combinesecret(splitData);
```

## Development

### Prerequisites

Install **WASI** and build tools:

```bash
cargo install wit-bindgen-cli
rustup target install wasm32-wasi wasm32-wasip1 wasm32-wasip2
cargo install cargo-component
npm install -g @bytecodealliance/jco
npm install -g @bytecodealliance/componentize-js
npm install -g @bytecodealliance/preview2-shim
```

### Build WASM

```bash
# Check and test
cargo component check
cargo component test

# Build release
cargo component build --release --target wasm32-wasip1

# Transpile to JavaScript
jco transpile target/wasm32-wasip1/release/vsss_wasm.wasm -o pkg
```

Or use the npm script:

```bash
npm run build:release
```

### Run Sample

```bash
cd sample
npm install
node --trace-warnings app.mjs
```

## API

- `generatesecret(): Uint8Array` - Generate a random 32-byte secret
- `splitsecret(secret: Uint8Array): Uint8Array` - Split secret of any size into shares + metadata
- `verifysecret(sharebytes: Uint8Array, verifybytes: Uint8Array): boolean` - Verify a share
- `combinesecret(fullData: Uint8Array): Uint8Array` - Reconstruct secret from full split output

**Output format from `splitsecret`:**

```
[shares (5 × 66 bytes)][verifier (variable)][encrypted secret (variable)][hash (32 bytes)]
```

**Important:** Pass the **full output** of `splitsecret` to `combinesecret` for reconstruction.

## License

Apache-2.0

## Author

Amin Razavi
