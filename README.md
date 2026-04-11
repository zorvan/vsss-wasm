# VSSS-WASM

Verifiable Shamir Secret Sharing over WASM for Node.js

## Description

Porting publicly verifiable shamir secret sharing from Rust to WASM for javascript.

**Features:**

- ✅ **Variable secret sizes** - Support secrets from 1 byte to kilobytes
- ✅ **Configurable shares** - Choose any shares/threshold combination (2-255 shares)
- ✅ **Cryptographic security** - Uses XChaCha20-Poly1305 encryption
- ✅ **Integrity verification** - SHA-256 hash verification on reconstruction
- ✅ **Share verification** - Verify individual shares against verifier set
- **Secret size**: Any size (1+ bytes)
- **Share size**: 66 bytes each (1 byte length + 32 bytes identifier + 1 byte length + 32 bytes value)
- **Total shares**: Configurable (default: 5)
- **Threshold**: Configurable (default: 3)

## Installation

```bash
npm install vsss-wasm
```

## Usage

```javascript
import { generatesecret, splitsecret, combinesecret } from "vsss-wasm";

// Generate a random 32-byte secret
const secret = generatesecret();

// Split secret with configurable shares and threshold
// Format: splitsecret(secret, sharesNumber, threshold)
const splitData = splitsecret(secret, 5, 3); // 5 shares, need 3 to reconstruct

// Reconstruct secret from full split data
const combinedSecret = combinesecret(splitData);
```

**Example with custom configuration:**

```javascript
// 4-of-7 configuration (higher security)
const mySecret = new Uint8Array(256);
// ... fill with your data ...

const splitData = splitsecret(mySecret, 7, 4);
// Store shares on different systems

// Later, reconstruct (need at least 4 shares)
const reconstructed = combinesecret(splitData);
```

## Performance Benchmarks

Benchmarks run on a typical modern machine (Node.js v20+, WASM). Results may vary based on hardware.

### Operation Performance (3-of-5, 32-byte secret)

| Operation        | Avg Time  | Ops/sec    | Description                |
|------------------|-----------|------------|----------------------------|
| Generate Secret  | ~14 μs    | ~70,000    | Generate 32-byte secret    |
| Split Secret     | ~237 μs   | ~4,200     | Split into 5 shares        |
| Verify Share     | ~24 μs    | ~42,000    | Verify single share        |
| Combine Secret   | ~73 μs    | ~13,700    | Reconstruct from shares    |

### Configuration Comparison (32-byte secret)

| Configuration      | Split     | Verify    | Combine   |
|--------------------|-----------|-----------|-----------|
| 2-of-3 (Minimal)   | 310 μs    | 31 μs     | 90 μs     |
| 3-of-5 (Standard)  | 314 μs    | 30 μs     | 100 μs    |
| 4-of-7 (Higher)    | 455 μs    | 34 μs     | 128 μs    |
| 5-of-10 (Maximum)  | 449 μs    | 42 μs     | 195 μs    |

### Secret Size Scaling (3-of-5 configuration)

| Secret Size | Split     | Verify    | Combine   | Throughput (Split) | Throughput (Combine) |
|-------------|-----------|-----------|-----------|--------------------|----------------------|
| 16 bytes    | 284 μs    | 29 μs     | 81 μs     | 4,200 ops/s        | 14,300 ops/s         |
| 32 bytes    | 356 μs    | 29 μs     | 83 μs     | 3,600 ops/s        | 13,900 ops/s         |
| 64 bytes    | 249 μs    | 27 μs     | 78 μs     | 4,200 ops/s        | 14,400 ops/s         |
| 128 bytes   | 249 μs    | 24 μs     | 75 μs     | 4,300 ops/s        | 14,300 ops/s         |
| 256 bytes   | 248 μs    | 57 μs     | 74 μs     | 4,300 ops/s        | 14,100 ops/s         |
| 512 bytes   | 263 μs    | 29 μs     | 83 μs     | 4,200 ops/s        | 13,500 ops/s         |
| 1024 bytes  | 244 μs    | 24 μs     | 81 μs     | 4,000 ops/s        | 12,300 ops/s         |

### Output Size Overhead (3-of-5 configuration)

The split output includes shares, verifier data, encrypted secret, and hash.

| Secret Size | Output Size | Overhead | Ratio  |
|-------------|-------------|----------|--------|
| 16 bytes    | 555 bytes   | 539 B    | 34.7x  |
| 32 bytes    | 571 bytes   | 539 B    | 17.8x  |
| 64 bytes    | 603 bytes   | 539 B    | 9.4x   |
| 128 bytes   | 667 bytes   | 539 B    | 5.2x   |
| 256 bytes   | 795 bytes   | 539 B    | 3.1x   |
| 512 bytes   | 1.03 KB     | 539 B    | 2.1x   |
| 1024 bytes  | 1.53 KB     | 539 B    | 1.5x   |

**Key Insights:**
- Performance is relatively constant across secret sizes (encryption is fast)
- Overhead decreases significantly with larger secrets (fixed ~539 bytes overhead)
- Higher threshold configurations have slightly higher combine times
- Share verification is extremely fast (~24-42 μs)

### Running Benchmarks

```bash
cd sample
npm install
node benchmark.mjs
```

## API

- `generatesecret(): Uint8Array` - Generate a random 32-byte secret
- `splitsecret(secret: Uint8Array, sharesNumber: number, threshold: number): Uint8Array` - Split secret with configurable shares and threshold
- `verifysecret(sharebytes: Uint8Array, verifybytes: Uint8Array): boolean` - Verify a share
- `combinesecret(fullData: Uint8Array): Uint8Array` - Reconstruct secret from full split output

**Output format from `splitsecret`:**

```
[header (4 bytes)][shares (N × 66 bytes)][verifier (variable)][encrypted secret (variable)][hash (32 bytes)]
```

Header structure:
- Byte 0: Number of shares
- Byte 1: Threshold
- Bytes 2-3: Verifier size (big-endian u16)

**Important:** Pass the **full output** of `splitsecret` to `combinesecret` for reconstruction. The function automatically parses the header to determine the data layout.

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

## License

Apache-2.0

## Author

Amin Razavi
