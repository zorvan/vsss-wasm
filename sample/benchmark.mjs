import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss-wasm";

// ============================================================================
// Benchmark Configuration
// ============================================================================

const BENCHMARK_CONFIGS = [
    // Different shares/threshold configurations
    { shares: 3, threshold: 2, label: "2-of-3 (Minimal)" },
    { shares: 5, threshold: 3, label: "3-of-5 (Standard)" },
    { shares: 7, threshold: 4, label: "4-of-7 (Higher Security)" },
    { shares: 10, threshold: 5, label: "5-of-10 (Maximum)" },
];

const SECRET_SIZES = [
    16,    // Small (e.g., AES-128 key)
    32,    // Standard (e.g., AES-256 key)
    64,    // Medium (e.g., EC private key)
    128,   // Large
    256,   // Extra large
    512,   // Very large
    1024,  // Kilobyte range
];

const ITERATIONS = 10; // Number of iterations for averaging

// ============================================================================
// Benchmark Utilities
// ============================================================================

function benchmark(fn, iterations = ITERATIONS) {
    // Warmup
    fn();
    
    // Benchmark
    const times = [];
    for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        fn();
        const end = performance.now();
        times.push(end - start);
    }
    
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);
    const median = times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
    
    return { avg, min, max, median, iterations };
}

function formatTime(ms) {
    if (ms < 1) {
        return `${(ms * 1000).toFixed(2)} μs`;
    } else if (ms < 1000) {
        return `${ms.toFixed(2)} ms`;
    } else {
        return `${(ms / 1000).toFixed(3)} s`;
    }
}

function formatBytes(bytes) {
    if (bytes < 1024) {
        return `${bytes} B`;
    } else if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(2)} KB`;
    } else {
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }
}

// ============================================================================
// Benchmark Functions
// ============================================================================

function benchmarkGenerateSecret(size) {
    return benchmark(() => {
        const secret = generatesecret();
        if (secret.length !== size) {
            throw new Error(`Expected ${size} bytes, got ${secret.length}`);
        }
    });
}

function benchmarkSplit(secret, shares, threshold) {
    return benchmark(() => {
        const result = splitsecret(secret, shares, threshold);
        if (!result || result.length === 0) {
            throw new Error("splitsecret returned empty result");
        }
    });
}

function benchmarkVerify(share, verifier) {
    return benchmark(() => {
        verifysecret(share, verifier);
    });
}

function benchmarkCombine(splitData) {
    return benchmark(() => {
        const result = combinesecret(splitData);
        if (!result || result.length === 0) {
            throw new Error("combinesecret returned empty result");
        }
    });
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================

console.log("╔══════════════════════════════════════════════════════════╗");
console.log("║         VSSS-WASM Performance Benchmark Suite           ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

// ------------------------------------------------------------------
// 1. Secret Generation Benchmark
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 1. Secret Generation Performance                        │");
console.log("└─────────────────────────────────────────────────────────┘\n");

const genBenchmark = benchmarkGenerateSecret(32);
console.log(`Generate 32-byte secret (${genBenchmark.iterations} iterations):`);
console.log(`  Avg: ${formatTime(genBenchmark.avg)} | Min: ${formatTime(genBenchmark.min)} | Max: ${formatTime(genBenchmark.max)} | Median: ${formatTime(genBenchmark.median)}\n`);

// ------------------------------------------------------------------
// 2. Configuration Comparison (fixed secret size)
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 2. Configuration Comparison (32-byte secret)            │");
console.log("└─────────────────────────────────────────────────────────┘\n");

const secret32 = generatesecret();

for (const config of BENCHMARK_CONFIGS) {
    console.log(`\n${config.label} Configuration:`);
    console.log(`  Shares: ${config.shares}, Threshold: ${config.threshold}`);
    
    const splitResult = benchmarkSplit(secret32, config.shares, config.threshold);
    console.log(`  Split:  ${formatTime(splitResult.avg)} avg (${formatBytes(splitResult.min / splitResult.iterations)} output size)`);
    
    // Extract share and verifier for verification benchmark
    const headerSize = 4;
    const encodedSize = 66;
    const sharesEnd = headerSize + (config.shares * encodedSize);
    const verifierSize = (splitResult.min / splitResult.iterations) - sharesEnd - 32 - (secret32.length + 24 + 16); // approximate
    const firstShare = splitResult.min > 0 ? new Uint8Array(66) : new Uint8Array(66);
    
    // Actually extract from a real split
    const splitData = splitsecret(secret32, config.shares, config.threshold);
    const actualVerifierEnd = splitData.length - 32 - (secret32.length + 24 + 16);
    const verifier = splitData.slice(sharesEnd, actualVerifierEnd);
    const firstShareActual = splitData.slice(headerSize, headerSize + encodedSize);
    
    const verifyResult = benchmarkVerify(firstShareActual, verifier);
    console.log(`  Verify: ${formatTime(verifyResult.avg)} avg (single share)`);
    
    const combineResult = benchmarkCombine(splitData);
    console.log(`  Combine: ${formatTime(combineResult.avg)} avg`);
}

console.log("\n");

// ------------------------------------------------------------------
// 3. Secret Size Scaling (fixed configuration)
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 3. Secret Size Scaling (3-of-5 configuration)           │");
console.log("└─────────────────────────────────────────────────────────┘\n");

const fixedConfig = { shares: 5, threshold: 3 };

for (const size of SECRET_SIZES) {
    const secret = new Uint8Array(size);
    crypto.getRandomValues(secret);
    
    const splitResult = benchmarkSplit(secret, fixedConfig.shares, fixedConfig.threshold);
    const splitData = splitsecret(secret, fixedConfig.shares, fixedConfig.threshold);
    
    // Extract for verify benchmark
    const headerSize = 4;
    const encodedSize = 66;
    const sharesEnd = headerSize + (fixedConfig.shares * encodedSize);
    const encryptedSize = secret.length + 24 + 16; // nonce + ciphertext + tag
    const verifierEnd = splitData.length - 32 - encryptedSize;
    const verifier = splitData.slice(sharesEnd, verifierEnd);
    const firstShare = splitData.slice(headerSize, headerSize + encodedSize);
    
    const verifyResult = benchmarkVerify(firstShare, verifier);
    const combineResult = benchmarkCombine(splitData);
    
    console.log(`${size.toString().padStart(4)} bytes | Split: ${formatTime(splitResult.avg).padStart(10)} | Verify: ${formatTime(verifyResult.avg).padStart(10)} | Combine: ${formatTime(combineResult.avg).padStart(10)}`);
}

console.log("\n");

// ------------------------------------------------------------------
// 4. Throughput Analysis
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 4. Throughput Analysis (3-of-5 configuration)           │");
console.log("└─────────────────────────────────────────────────────────┘\n");

for (const size of SECRET_SIZES) {
    const secret = new Uint8Array(size);
    crypto.getRandomValues(secret);
    
    const splitResult = benchmarkSplit(secret, 5, 3);
    const splitData = splitsecret(secret, 5, 3);
    const combineResult = benchmarkCombine(splitData);
    
    // Calculate throughput (operations per second)
    const splitOpsPerSec = 1000 / splitResult.avg;
    const combineOpsPerSec = 1000 / combineResult.avg;
    
    // Calculate MB/s
    const splitMBps = (splitOpsPerSec * size) / (1024 * 1024);
    const combineMBps = (combineOpsPerSec * size) / (1024 * 1024);
    
    console.log(`${size.toString().padStart(4)} bytes | Split: ${splitOpsPerSec.toFixed(1).padStart(8)} ops/s (${splitMBps.toFixed(2).padStart(8)} MB/s) | Combine: ${combineOpsPerSec.toFixed(1).padStart(8)} ops/s (${combineMBps.toFixed(2).padStart(8)} MB/s)`);
}

console.log("\n");

// ------------------------------------------------------------------
// 5. Output Size Analysis
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 5. Output Size Overhead (3-of-5 configuration)          │");
console.log("└─────────────────────────────────────────────────────────┘\n");

console.log("Secret Size | Split Output | Overhead | Ratio");
console.log("───────────┼──────────────┼──────────┼───────");

for (const size of SECRET_SIZES) {
    const secret = new Uint8Array(size);
    crypto.getRandomValues(secret);
    
    const splitData = splitsecret(secret, 5, 3);
    const overhead = splitData.length - size;
    const ratio = (splitData.length / size).toFixed(2);
    
    console.log(`${size.toString().padStart(10)} B | ${formatBytes(splitData.length).padStart(12)} | ${formatBytes(overhead).padStart(8)} | ${ratio}x`);
}

console.log("\n");

// ------------------------------------------------------------------
// 6. Performance Summary Table
// ------------------------------------------------------------------
console.log("┌─────────────────────────────────────────────────────────┐");
console.log("│ 6. Performance Summary (3-of-5, 32-byte secret)         │");
console.log("└─────────────────────────────────────────────────────────┘\n");

const testSecret = new Uint8Array(32);
crypto.getRandomValues(testSecret);

const genPerf = benchmarkGenerateSecret(32);
const splitPerf = benchmarkSplit(testSecret, 5, 3);
const splitData = splitsecret(testSecret, 5, 3);
const headerSize = 4;
const encodedSize = 66;
const sharesEnd = headerSize + (5 * encodedSize);
const encryptedSize = 32 + 24 + 16;
const verifierEnd = splitData.length - 32 - encryptedSize;
const verifier = splitData.slice(sharesEnd, verifierEnd);
const firstShare = splitData.slice(headerSize, headerSize + encodedSize);
const verifyPerf = benchmarkVerify(firstShare, verifier);
const combinePerf = benchmarkCombine(splitData);

console.log("Operation          | Avg Time    | Ops/sec     | Throughput");
console.log("───────────────────┼─────────────┼─────────────┼────────────");
console.log(`Generate Secret    | ${formatTime(genPerf.avg).padStart(11)} | ${(1000 / genPerf.avg).toFixed(1).padStart(9)} ops/s | N/A`);
console.log(`Split Secret       | ${formatTime(splitPerf.avg).padStart(11)} | ${(1000 / splitPerf.avg).toFixed(1).padStart(9)} ops/s | N/A`);
console.log(`Verify Share       | ${formatTime(verifyPerf.avg).padStart(11)} | ${(1000 / verifyPerf.avg).toFixed(1).padStart(9)} ops/s | N/A`);
console.log(`Combine Secret     | ${formatTime(combinePerf.avg).padStart(11)} | ${(1000 / combinePerf.avg).toFixed(1).padStart(9)} ops/s | N/A`);

console.log("\n✅ Benchmark suite completed successfully!\n");
