# Description
Publicly verifiable shamir secret sharing in rust/wasm.

secret size = 32 bytes
verifier size = 32 bytes. (optional)

# Run
```python
python -m simple_http_server
```

open localhost:9090/web.html
look at console logs.

to install python simple web server : 
``` shell
python -m pip install simple-http-server
```

# Compile Wasm

``` shell
wasm-pack build --target web
```
There are other targets : nodejs, bundle

wasm-pack can be installed with :
``` shell
cargo install wasm-pack
```
