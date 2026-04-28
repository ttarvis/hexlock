#!/usr/bin/env bash
set -euo pipefail

PCRE2_VERSION="10.47"
PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"

TARGET_ARCH="${1:-}"
SRC_DIR="${2:-external/pcre2}"
PREFIX="${3:-}"

if [ -n "$TARGET_ARCH" ]; then
    HOST_FLAG="--host=${TARGET_ARCH}-apple-darwin"
    ARCH_CFLAG="-arch ${TARGET_ARCH}"
else
    HOST_FLAG=""
    ARCH_CFLAG=""
fi

mkdir -p "${SRC_DIR}"
curl -fL "${PCRE2_URL}" -o "${SRC_DIR}/pcre2.tar.gz"
tar -xzf "${SRC_DIR}/pcre2.tar.gz" -C "${SRC_DIR}" --strip-components=1

cd "${SRC_DIR}"

if [ -z "$PREFIX" ]; then
    PREFIX="$(pwd)/build"
fi

./configure \
    --prefix="${PREFIX}" \
    --disable-shared \
    --enable-static \
    ${HOST_FLAG} \
    CFLAGS="-fPIC ${ARCH_CFLAG}"
make -j"$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)"
make install
