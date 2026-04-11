import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss-wasm";

const SHARES = 5;
const ENCODED_SIZE = 66; // 1 (len) + 32 (identifier) + 1 (len) + 32 (value)

// Generate a secret
const secret = generatesecret();
console.log("secret = " + secret  + "\n");

// Secret Sharing
const split = splitsecret(secret);

// Extract verifier (comes after all shares)
const sharesEnd = SHARES * ENCODED_SIZE;
const verifier = split.slice(sharesEnd);

console.log("split total size = " + split.length);
console.log("shares size = " + sharesEnd);
console.log("verifier size = " + verifier.length + "\n");

// Verify each share
for (let i = 0; i < SHARES; i++) {
    const shareStart = i * ENCODED_SIZE;
    const share = split.slice(shareStart, shareStart + ENCODED_SIZE);
    const shareId = share[33]; // ID is at byte 33 (after identifier length + identifier)
    
    console.log("share " + (i + 1) + " (id=" + shareId + ")");
    const isValid = verifysecret(share, verifier);
    console.log("  valid? " + isValid + "\n");
}

// Combine shares (need THRESHOLD=3 shares, using shares 3, 4, 5)
const sharesStartIndex = 2 * ENCODED_SIZE; // Start from share 3 (index 2)
const sharesToCombine = split.slice(sharesStartIndex, sharesEnd);

console.log("Combining shares 3, 4, 5...");
const combinedSecret = combinesecret(sharesToCombine);
console.log("combined secret = " + combinedSecret);
console.log("matches original? " + (combinedSecret.toString() === secret.toString()));
