#!/bin/bash
set -e

echo "Building VSSS-WASM package..."

# Build WASM
echo "Running cargo component build..."
cargo component build --release --target wasm32-wasip1

# Transpile to JavaScript
echo "Running jco transpile..."
jco transpile target/wasm32-wasip1/release/vsss_wasm.wasm -o pkg

echo "Build complete! Output is in pkg/ directory"
