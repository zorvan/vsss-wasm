import * as wasm from "./vsss_wasm.js";

const secret = wasm.generate_secret()
console.log({ secret })
const res = wasm.split_secret(secret)
console.log({ res })



