import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss-wasm";

const SHARES = 5;
const ENCODED_SIZE = 66; // 1 (len) + 32 (identifier) + 1 (len) + 32 (value)

console.log("=== Test 1: 32-byte secret (default) ===");
const secret32 = generatesecret();
console.log("secret (32 bytes) = " + secret32 + "\n");
testSecret(secret32);

console.log("\n=== Test 2: 16-byte secret ===");
const secret16 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
testSecret(secret16);

console.log("\n=== Test 3: 64-byte secret ===");
const secret64 = new Uint8Array(64);
for (let i = 0; i < 64; i++) secret64[i] = i;
testSecret(secret64);

console.log("\n=== Test 4: 256-byte secret (large) ===");
const secret256 = new Uint8Array(256);
crypto.getRandomValues(secret256);
testSecret(secret256);

function testSecret(secret) {
    console.log(`Secret size: ${secret.length} bytes`);
    
    // Split secret
    const split = splitsecret(secret);
    
    // Extract shares and verifier
    const sharesEnd = SHARES * ENCODED_SIZE;
    const verifier = split.slice(sharesEnd, split.length - 32); // Last 32 bytes is hash
    console.log(`Split output size: ${split.length} bytes`);
    console.log(`Verifier size: ${verifier.length} bytes\n`);
    
    // Verify each share
    for (let i = 0; i < SHARES; i++) {
        const shareStart = i * ENCODED_SIZE;
        const share = split.slice(shareStart, shareStart + ENCODED_SIZE);
        const isValid = verifysecret(share, verifier);
        console.log(`Share ${i + 1}: valid = ${isValid}`);
    }
    
    // Combine shares (using shares 3, 4, 5)
    const sharesToCombine = split.slice(2 * ENCODED_SIZE, sharesEnd);
    const combinedSecret = combinesecret(split); // Pass full data
    
    const matches = combinedSecret.toString() === secret.toString();
    console.log(`\nCombined secret matches original: ${matches}`);
    
    if (!matches) {
        console.log("Original: ", secret);
        console.log("Combined: ", combinedSecret);
    }
}
