# VSSS-WASM Performance Benchmarks

**Date:** 2026-04-11  
**Environment:** Node.js WASM (typical modern machine)  
**Test Configurations:** Various shares/threshold combinations  
**Iterations:** 10 per measurement (averaged)

---

## Executive Summary

VSSS-WASM provides fast verifiable secret sharing with the following characteristics:

- **Split Operation:** ~237-455 μs (4,000-4,300 ops/s)
- **Combine Operation:** ~73-195 μs (12,000-14,000 ops/s)  
- **Verify Operation:** ~24-42 μs (24,000-42,000 ops/s)
- **Fixed Overhead:** ~539 bytes per split output
- **Performance:** Relatively constant across secret sizes (16-1024 bytes)

---

## Detailed Results

### 1. Operation Performance (3-of-5, 32-byte secret)

| Operation        | Avg Time  | Ops/sec    | Description                |
|------------------|-----------|------------|----------------------------|
| Generate Secret  | ~14 μs    | ~70,000    | Generate 32-byte secret    |
| Split Secret     | ~237 μs   | ~4,200     | Split into 5 shares        |
| Verify Share     | ~24 μs    | ~42,000    | Verify single share        |
| Combine Secret   | ~73 μs    | ~13,700    | Reconstruct from shares    |

### 2. Configuration Comparison (32-byte secret)

| Configuration      | Split     | Verify    | Combine   |
|--------------------|-----------|-----------|-----------|
| 2-of-3 (Minimal)   | 310 μs    | 31 μs     | 90 μs     |
| 3-of-5 (Standard)  | 314 μs    | 30 μs     | 100 μs    |
| 4-of-7 (Higher)    | 455 μs    | 34 μs     | 128 μs    |
| 5-of-10 (Maximum)  | 449 μs    | 42 μs     | 195 μs    |

### 3. Secret Size Scaling (3-of-5 configuration)

| Secret Size | Split     | Verify    | Combine   | Throughput (Split) | Throughput (Combine) |
|-------------|-----------|-----------|-----------|--------------------|----------------------|
| 16 bytes    | 284 μs    | 29 μs     | 81 μs     | 4,200 ops/s        | 14,300 ops/s         |
| 32 bytes    | 356 μs    | 29 μs     | 83 μs     | 3,600 ops/s        | 13,900 ops/s         |
| 64 bytes    | 249 μs    | 27 μs     | 78 μs     | 4,200 ops/s        | 14,400 ops/s         |
| 128 bytes   | 249 μs    | 24 μs     | 75 μs     | 4,300 ops/s        | 14,300 ops/s         |
| 256 bytes   | 248 μs    | 57 μs     | 74 μs     | 4,300 ops/s        | 14,100 ops/s         |
| 512 bytes   | 263 μs    | 29 μs     | 83 μs     | 4,200 ops/s        | 13,500 ops/s         |
| 1024 bytes  | 244 μs    | 24 μs     | 81 μs     | 4,000 ops/s        | 12,300 ops/s         |

### 4. Output Size Overhead (3-of-5 configuration)

| Secret Size | Output Size | Overhead | Ratio  |
|-------------|-------------|----------|--------|
| 16 bytes    | 555 bytes   | 539 B    | 34.7x  |
| 32 bytes    | 571 bytes   | 539 B    | 17.8x  |
| 64 bytes    | 603 bytes   | 539 B    | 9.4x   |
| 128 bytes   | 667 bytes   | 539 B    | 5.2x   |
| 256 bytes   | 795 bytes   | 539 B    | 3.1x   |
| 512 bytes   | 1.03 KB     | 539 B    | 2.1x   |
| 1024 bytes  | 1.53 KB     | 539 B    | 1.5x   |

---

## Key Insights

### Performance Characteristics

1. **Constant-Time Operations:** Performance is relatively constant across secret sizes (16-1024 bytes) because encryption (XChaCha20-Poly1305) is very fast.

2. **Configuration Impact:** 
   - Higher threshold increases combine time (more shares to process)
   - Split time increases moderately with threshold
   - Verify time remains fast across all configurations

3. **Throughput:**
   - Split: ~4,000 ops/s (consistent across sizes)
   - Combine: ~12,000-14,000 ops/s (3x faster than split)
   - Verify: ~24,000-42,000 ops/s (fastest operation)

### Overhead Analysis

1. **Fixed Overhead:** ~539 bytes per split output (shares + verifier + encryption metadata)
2. **Ratio Decreases:** Overhead ratio drops significantly with larger secrets
   - 34.7x for 16-byte secrets
   - 1.5x for 1024-byte secrets
3. **Best Efficiency:** Use with secrets ≥256 bytes for <3x overhead

### Recommendations

- **For Key Storage:** 3-of-5 configuration provides good balance
- **For High Security:** 4-of-7 or 5-of-10 for distributed systems
- **For Minimal Overhead:** Use larger secrets or batch operations
- **For Performance:** Combine operations are 3x faster than split operations

---

## Running Benchmarks

```bash
cd sample
npm install
node benchmark.mjs
```

The benchmark suite tests:
- Secret generation performance
- Configuration comparisons (2-of-3, 3-of-5, 4-of-7, 5-of-10)
- Secret size scaling (16-1024 bytes)
- Throughput analysis
- Output size overhead

---

## Technical Details

### Cryptographic Operations

- **Key Derivation:** Scalar from random bytes (Curve25519)
- **Secret Sharing:** Feldman Verifiable Secret Sharing Scheme
- **Encryption:** XChaCha20-Poly1305 (AEAD)
- **Hashing:** SHA-256 for integrity verification

### Output Format

```
[header (4 bytes)][shares (N × 66 bytes)][verifier (variable)][encrypted secret (variable)][hash (32 bytes)]
```

Header:
- Byte 0: Number of shares
- Byte 1: Threshold
- Bytes 2-3: Verifier size (big-endian u16)

### Implementation

- **Language:** Rust (compiled to WASM)
- **Target:** wasm32-wasip1
- **Dependencies:** vsss-rs, curve25519-dalek, chacha20poly1305, sha2

---

**Note:** Results may vary based on hardware, Node.js version, and system load. Benchmarks represent typical performance on modern machines.
