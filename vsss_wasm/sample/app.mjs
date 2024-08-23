import { generatesecret, splitsecret, verifysecret, combinesecret } from "vsss_wasm";

const SHARES = 5;
const SHARESIZE = 32;
const ENCODEDSIZE = SHARESIZE + 2;

// Generate a secret
const secret = generatesecret();
console.log("secret = " + secret  + "\n\n");

// Secret Sharing
const split = splitsecret(secret);

// Verifier
const verifier = split.slice(SHARES*ENCODEDSIZE)
console.log("splitted secret verifier = " + verifier+ "\n\n");

for (let i = 0; i < SHARES; i++) {
    const shareid = split[i*ENCODEDSIZE + 1];
    const share = split.slice(i*ENCODEDSIZE, (i+1) * ENCODEDSIZE);
    console.log("splitted secret " + shareid + " = " + share.slice(2));
    const verify = verifysecret(share, verifier);
    console.log("valid secret? => " + verify + "\n");
}


const combinedsecret = combinesecret(split.slice(0,3*ENCODEDSIZE));
console.log("combined secret = " + combinedsecret)
