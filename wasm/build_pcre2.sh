#!/bin/bash
# Cross-compile PCRE2 for Emscripten/WASM (JIT disabled for WASM)
set -e

PCRE2_VERSION="10.44"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/pcre2-build"
INSTALL_DIR="$SCRIPT_DIR/prebuilt"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -f "pcre2-$PCRE2_VERSION.tar.gz" ]; then
    wget -q "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/pcre2-$PCRE2_VERSION.tar.gz"
fi

rm -rf "pcre2-$PCRE2_VERSION"
tar -xzf "pcre2-$PCRE2_VERSION.tar.gz"
cd "pcre2-$PCRE2_VERSION"

emconfigure ./configure \
    --prefix="$INSTALL_DIR" \
    --disable-shared \
    --enable-static \
    --disable-jit \
    --enable-unicode \
    --host=wasm32-unknown-emscripten

emmake make -j$(nproc)
emmake make install

echo "PCRE2 installed to $INSTALL_DIR"
