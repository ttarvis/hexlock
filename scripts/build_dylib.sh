#!/usr/bin/env bash
set -euo pipefail

TARGET_ARCH="$1"
PCRE2_PREFIX="$2"
OUTPUT="$3"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Set minimum macOS deployment target so the dylib is compatible with
# the oldest macOS version cibuildwheel targets. Without this, clang
# defaults to the host OS version (e.g. 15.0) and delocate rejects it.
if [ "$TARGET_ARCH" = "arm64" ]; then
    export MACOSX_DEPLOYMENT_TARGET="11.0"
else
    export MACOSX_DEPLOYMENT_TARGET="10.9"
fi

make -C "${REPO_ROOT}/lib" clean
make -C "${REPO_ROOT}/lib" \
    CC=clang \
    ARCH_FLAGS="-arch ${TARGET_ARCH}" \
    PCRE2_LIB="${PCRE2_PREFIX}/lib/libpcre2-8.a" \
    CFLAGS="-Wall -Wextra -O2 -fPIC -arch ${TARGET_ARCH} -Iinclude -Ifpe -Iregex -Itokenizer -I${PCRE2_PREFIX}/include"

cp "${REPO_ROOT}/lib/libhexlock.dylib" "${OUTPUT}"
