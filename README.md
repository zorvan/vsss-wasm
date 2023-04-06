# Description
Porting publicly verifiable shamir secret sharing from Rust to WASM for javascript.

secret size = 32 bytes.

verifier size = 130 bytes. (optional)

# Compile Wasm

install **wasm-pack**  :
``` shell
$ cargo install wasm-pack
```

to build the project : 

``` shell
$ wasm-pack build --release --target web
```
There are other targets : nodejs, bundle


# Run

## Web sample
You can use any web server, here I use python.

To install Python simple web server : 
``` shell
$ python -m pip install simple-http-server
```

run these commands : 

``` shell
$ cd samples/web-pkg
$ python -m simple_http_server
```

then open [localhost:9090/web.html](localhost:9090/web.html)

then look at browser console logs in verbose mode.

## Node.js sample

``` shell
$ cd samples/node-pkg
$ node --trace-warnings app.mjs
```
