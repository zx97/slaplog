#!/usr/bin/env bash
#
# build_liblzma.sh - Cross-build liblzma (from xz-utils) for WebAssembly.
#
# WHY THIS EXISTS
# ---------------
# log_parser.cpp references the xz decompression API (lzma_stream_decoder,
# lzma_code, lzma_end, ...).  Emscripten ships official ports for zlib
# (-sUSE_ZLIB=1) and bzip2 (-sUSE_BZIP2=1), but NOT for xz/liblzma.  So we
# cross-compile a static liblzma.a here, once, and link it into the WASM
# build.
#
# This script is only ever invoked by `make wasm`.  The native build (plain
# `make`) never touches it.
#
# OUTPUTS
# -------
#   wasm/prebuilt/liblzma.a        static library, wasm32
#   wasm/prebuilt/include/lzma.h   public header
#   wasm/prebuilt/include/lzma/    per-filter headers
#
# The prebuilt artefacts are git-ignored; running this script regenerates them.
#
# IDEMPOTENCE
# -----------
# If the outputs already exist the script exits immediately.  Set FORCE=1 to
# rebuild from scratch.
#
set -euo pipefail

XZ_VERSION="${XZ_VERSION:-5.6.4}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/wasm/prebuilt"
WORK_DIR="${WORK_DIR:-/tmp/opencode/slaplog-liblzma}"

log() { printf '[liblzma] %s\n' "$*"; }

if [[ -f "$OUT_DIR/liblzma.a" && "${FORCE:-0}" != "1" ]]; then
    log "already built: $OUT_DIR/liblzma.a (FORCE=1 to rebuild)"
    exit 0
fi

for tool in emconfigure emmake emar; do
    command -v "$tool" >/dev/null 2>&1 || {
        log "ERROR: '$tool' not found. Activate the Emscripten SDK first."
        exit 1
    }
done

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

TARBALL="xz-$XZ_VERSION.tar.gz"
SRC_DIR="xz-$XZ_VERSION"

if [[ ! -f "$TARBALL" ]]; then
    log "downloading xz $XZ_VERSION"
    curl -fL --retry 3 --retry-delay 2 -o "$TARBALL" \
        "https://github.com/tukaani-project/xz/releases/download/v$XZ_VERSION/$TARBALL" \
    || curl -fL --retry 3 --retry-delay 2 -o "$TARBALL" \
        "https://tukaani.org/xz/$TARBALL"
fi

rm -rf "$SRC_DIR"
tar xf "$TARBALL"
cd "$SRC_DIR"

# Build only liblzma: disable every command-line tool and auxiliary program so
# that nothing needs to be executed at build time (cross-compiling friendly).
log "configuring (wasm32)"
emconfigure ./configure \
    --disable-shared \
    --enable-static \
    --disable-xz \
    --disable-xzdec \
    --disable-lzmadec \
    --disable-lzmainfo \
    --disable-scripts \
    --disable-nls \
    CFLAGS="-O2"

log "building"
emmake make -j"$(nproc)"

log "staging artefacts"
cp src/liblzma/.libs/liblzma.a "$OUT_DIR/liblzma.a"

rm -rf "$OUT_DIR/include"
mkdir -p "$OUT_DIR/include"
cp src/liblzma/api/lzma.h "$OUT_DIR/include/"
cp -r src/liblzma/api/lzma "$OUT_DIR/include/"

log "OK -> $OUT_DIR/liblzma.a"
