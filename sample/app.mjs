import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss-wasm";

const SHARES = 5;
const THRESHOLD = 3;
const HEADER_SIZE = 4; // shares_count(1) + threshold(1) + verifier_size(2)
const ENCODED_SIZE = 66; // 1 (len) + 32 (identifier) + 1 (len) + 32 (value)

console.log("=== Test 1: 32-byte secret (default) ===");
const secret32 = generatesecret();
console.log("secret (32 bytes) = " + secret32 + "\n");
testSecret(secret32, SHARES, THRESHOLD);

console.log("\n=== Test 2: 16-byte secret ===");
const secret16 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
testSecret(secret16, SHARES, THRESHOLD);

console.log("\n=== Test 3: 64-byte secret ===");
const secret64 = new Uint8Array(64);
for (let i = 0; i < 64; i++) secret64[i] = i;
testSecret(secret64, SHARES, THRESHOLD);

console.log("\n=== Test 4: 256-byte secret (large) ===");
const secret256 = new Uint8Array(256);
crypto.getRandomValues(secret256);
testSecret(secret256, SHARES, THRESHOLD);

console.log("\n=== Test 5: 4-of-7 configuration ===");
const secret7of4 = generatesecret();
testSecret(secret7of4, 7, 4);

function testSecret(secret, shares, threshold) {
    console.log(`Secret size: ${secret.length} bytes`);
    console.log(`Configuration: ${shares}-of-${threshold}`);

    // Split secret with configurable shares and threshold
    const split = splitsecret(secret, shares, threshold);

    // Extract shares and verifier using header information
    const sharesEnd = HEADER_SIZE + (shares * ENCODED_SIZE);
    const verifier = split.slice(sharesEnd, split.length - 32); // Last 32 bytes is hash
    console.log(`Split output size: ${split.length} bytes`);
    console.log(`Verifier size: ${verifier.length} bytes\n`);

    // Verify each share
    for (let i = 0; i < shares; i++) {
        const shareStart = HEADER_SIZE + (i * ENCODED_SIZE);
        const share = split.slice(shareStart, shareStart + ENCODED_SIZE);
        const isValid = verifysecret(share, verifier);
        console.log(`Share ${i + 1}: valid = ${isValid}`);
    }

    // Combine shares (pass full data)
    const combinedSecret = combinesecret(split);

    const matches = combinedSecret.toString() === secret.toString();
    console.log(`\nCombined secret matches original: ${matches}`);

    if (!matches) {
        console.log("Original: ", secret);
        console.log("Combined: ", combinedSecret);
    }
}
