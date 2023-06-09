import * as vsss from "./vsss_wasm.js";
const SHARE_SIZE = 34;

const secret = vsss.generate_secret()
console.log(secret);

const out = vsss.split_secret(secret);

var share1 = out.slice(0  ,SHARE_SIZE);
console.log("share1 : ", buf2hex(share1));
var share2 = out.slice(SHARE_SIZE ,2*SHARE_SIZE);
console.log("share2 : ", buf2hex(share2));
var share3 = out.slice(2*SHARE_SIZE ,3*SHARE_SIZE);
console.log("share3 : ", buf2hex(share3));
var share4 = out.slice(3*SHARE_SIZE ,4*SHARE_SIZE);
console.log("share4 : ", buf2hex(share4));
var share5 = out.slice(4*SHARE_SIZE,5*SHARE_SIZE);
console.log("share5 : ", buf2hex(share5));

var verifier = out.slice(5*SHARE_SIZE); // to the end

// sample verification of share num.3
var verify = vsss.verify_secret(share3, verifier);
console.log("verify 3rd share : ", verify);

// combining sample shares 1,3,5 it can be any number of shares. but for less than threshold it will fail!
var selected_shares = new Uint8Array([ ...share3, ...share1, ...share5 ]);

var reconstructed_secret = vsss.combine_secret(selected_shares);
console.log("combined secret : ", buf2hex(reconstructed_secret));

console.log("combined secret : ", reconstructed_secret);

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
  }
