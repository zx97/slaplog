#!/usr/bin/env bash
#
# build-local.sh — build the release artefacts for the current machine:
#   dist/slaplog-<version>-linux-<arch>.tar.gz
#   dist/slaplog_<version>-1_<debarch>.deb
#   dist/slaplog-<version>-1.<rpmarch>.rpm
#   dist/SHA256SUMS
#
# By default the binary is built inside an AlmaLinux 9 container, exactly like
# CI: glibc 2.34, GCC 11, explicit instruction-set baseline.  This is what
# makes the artefacts run on Debian 12+, Ubuntu 22.04+ and RHEL 9+.
#
# Usage:
#   packaging/build-local.sh              # portable build (needs podman)
#   packaging/build-local.sh --container  # also build the container image
#   packaging/build-local.sh --native     # host build, for testing only
#
# nfpm is required for the .deb/.rpm:
#   https://github.com/goreleaser/nfpm/releases
# Put it in PATH, or set NFPM=/path/to/nfpm.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(sed -n 's/^#define SLAPLOG_VERSION "\(.*\)"/\1/p' "$ROOT/version.hpp")
[ -n "$VERSION" ] || { echo "cannot read SLAPLOG_VERSION" >&2; exit 1; }

MODE=container
CONTAINER=0
for arg in "$@"; do
    case "$arg" in
        --native)    MODE=native ;;
        --container) CONTAINER=1 ;;
        *) echo "usage: $0 [--native] [--container]" >&2; exit 2 ;;
    esac
done

case "$(uname -m)" in
    x86_64)          DEB_ARCH=amd64; RPM_ARCH=x86_64;  SIMD="-march=x86-64-v2" ;;
    aarch64|arm64)   DEB_ARCH=arm64; RPM_ARCH=aarch64; SIMD="-march=armv8-a" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

NFPM=${NFPM:-$(command -v nfpm || true)}
[ -n "$NFPM" ] || {
    echo "nfpm not found; install it from https://github.com/goreleaser/nfpm/releases" >&2
    echo "or set NFPM=/path/to/nfpm" >&2
    exit 1
}

DIST="$ROOT/dist"
PKGROOT="$ROOT/pkgroot"
rm -rf "$DIST" "$PKGROOT"
mkdir -p "$DIST" "$PKGROOT/doc"

VOLUME=""
cleanup() { [ -n "$VOLUME" ] && podman volume rm -f "$VOLUME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

if [ "$MODE" = native ]; then
    echo "== host build (--native): the binary needs this host's glibc, do not publish it"
    make -C "$ROOT" -j"$(nproc)" SIMD_FLAGS="$SIMD"
    BIN="$ROOT/slaplog"
else
    command -v podman >/dev/null 2>&1 || {
        echo "podman is required for a portable build; use --native for a host build" >&2
        exit 1
    }
    VOLUME="slaplog-build-$$"
    echo "== building slaplog $VERSION for $DEB_ARCH in AlmaLinux 9 ($SIMD)"
    podman volume create "$VOLUME" >/dev/null
    podman run --rm --security-opt label=disable \
        -v "$ROOT:/src:ro" -v "$VOLUME:/build" -w /build \
        -e SIMD_FLAGS="$SIMD" \
        almalinux:9 bash -c '
            set -e
            dnf install -y -q epel-release
            dnf install -y -q gcc-c++ make git tar gzip bzip2 xz diffutils \
                pcre2-devel zlib-devel bzip2-devel xz-devel json-devel time python3
            tar -C /src --exclude=dist --exclude=pkgroot \
                --exclude=stage --exclude="*.o" --exclude="*.d" \
                --exclude=slaplog -cf - . | tar -xf -
            make -j"$(nproc)" SIMD_FLAGS="$SIMD_FLAGS"
            make check
        '
    BIN="$DIST/slaplog-linux-$DEB_ARCH"
    podman run --rm -v "$VOLUME:/build:ro" almalinux:9 cat /build/slaplog > "$BIN"
    chmod 0755 "$BIN"
fi

echo "== staging the tarball and the packages"
STAGE="$DIST/slaplog-$VERSION-linux-$DEB_ARCH"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/slaplog"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$STAGE/"
cp "$ROOT/doc/slaplog.md" "$STAGE/"
tar -C "$DIST" -czf "$DIST/slaplog-$VERSION-linux-$DEB_ARCH.tar.gz" \
    "slaplog-$VERSION-linux-$DEB_ARCH"
rm -rf "$STAGE"

cp "$BIN" "$PKGROOT/slaplog"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$PKGROOT/"
cp "$ROOT/doc/slaplog.md" "$PKGROOT/doc/"

(cd "$PKGROOT" && PKG_VERSION="$VERSION" PKG_ARCH="$DEB_ARCH" \
    "$NFPM" package -f "$ROOT/packaging/nfpm.yaml" -p deb -t "$DIST/")
(cd "$PKGROOT" && PKG_VERSION="$VERSION" PKG_ARCH="$RPM_ARCH" \
    "$NFPM" package -f "$ROOT/packaging/nfpm.yaml" -p rpm -t "$DIST/")

(cd "$DIST" && sha256sum ./*.tar.gz ./*.deb ./*.rpm > SHA256SUMS)

if [ "$CONTAINER" = 1 ]; then
    command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; exit 1; }
    echo "== building container image slaplog:$VERSION"
    podman build --build-arg "TARGETARCH=$DEB_ARCH" --build-arg "VERSION=$VERSION" \
        -t "slaplog:$VERSION" -t slaplog:latest "$ROOT"
fi

echo
echo "artefacts in $DIST:"
ls -1 "$DIST"
