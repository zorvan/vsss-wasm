# Description
Porting publicly verifiable shamir secret sharing from Rust to WASM for javascript.

secret size = 32 bytes.

verifier size = 130 bytes. (optional)

# Compile Wasm

# Compile Wasm

install **WASI**  :

``` shell
$ npm install -g @bytecodealliance/jco
$ npm install -g @bytecodealliance/componentize-js
$ rustup target install wasm32-wasi wasm32-wasip1 wasm32-wasip2
$ cargo install cargo-component
```

``` shell
$ cargo component check
$ cargo component test
$ cargo component build --release
```

``` shell
$ jco transpile target/wasm32-wasip1/release/vsss_wasm.wasm -o target
```

# Run

## Node.js sample

``` shell
$ cd vss_wasm/sample/node-pkg
$ npm install
$ node --trace-warnings app.mjs
```
