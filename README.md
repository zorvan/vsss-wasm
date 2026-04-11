# VSSS-WASM

Verifiable Shamir Secret Sharing over WASM for Node.js

## Description

Porting publicly verifiable shamir secret sharing from Rust to WASM for javascript.

- **Secret size**: 32 bytes
- **Share size**: 66 bytes (1 byte length + 32 bytes identifier + 1 byte length + 32 bytes value)
- **Verifier size**: ~133 bytes
- **Total shares**: 5
- **Threshold**: 3 (minimum shares needed to reconstruct)

## Installation

```bash
npm install vsss-wasm
```

## Usage

```javascript
import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss-wasm";

// Generate a secret
const secret = generatesecret();

// Split the secret into shares
const split = splitsecret(secret);

// Verify and combine shares
const combinedsecret = combinesecret(split.slice(0, 3 * 34));
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
- `splitsecret(secret: Uint8Array): Uint8Array` - Split secret into shares
- `verifysecret(sharebytes: Uint8Array, verifybytes: Uint8Array): boolean` - Verify a share
- `combinesecret(sharebytes: Uint8Array): Uint8Array` - Combine shares to recover secret

## License

Apache-2.0

## Author

Amin Razavi
