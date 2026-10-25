#!/usr/bin/env bash
#
# Fetches pyke's prebuilt, statically linkable ONNX Runtime and verifies it
# before Cargo sees it. `.cargo/config.toml` points `ORT_LIB_PATH` at the
# extracted directory and sets `ORT_SKIP_DOWNLOAD=1`, so every build links
# this archive and `ort-sys` never downloads one of its own.
#
# Pinned to ONNX Runtime 1.28.0 (tag v1.28.0), the build `ort` 2.0.0-rc.13
# expects. URL and hash come from ort-sys rc.13 `build/download/dist.tsv`.
# `ort` is now 2.0.0-rc.15, which pairs with 1.31.0 but runs on 1.28.0: it
# asks ONNX Runtime only for API 17. Bumping this archive means bumping the
# URL, the hash, `ORT_LIB_PATH` in `.cargo/config.toml`, the CI cache key,
# the pinned-version test in `voidwall-ml`, and the files in `licenses/`.
#
# Needs: curl, sha256sum, xz, tar, and gh >= 2.49 logged in or with GH_TOKEN.
#
# Usage:
#   docker/fetch-ort.sh                 # fetch, verify, extract (skips if done)
#   docker/fetch-ort.sh --verify FILE   # run only the hash and attestation checks
#
set -euo pipefail

ORT_VERSION="1.28.0"
ORT_URL="https://cdn.pyke.io/0/pyke:ort-rs/ms@${ORT_VERSION}/x86_64-unknown-linux-gnu.tar.lzma2"
ORT_SHA256="e454f710f8a49f53aa5b4ff51e3454ae1835777e431c6c35c5255ce6f205fd68"
ATTESTATION_OWNER="pykeio"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST_DIR="$PROJECT_DIR/.ort/$ORT_VERSION"
LIB="$DEST_DIR/libonnxruntime.a"
STAMP="$DEST_DIR/.verified"

die() {
    echo "fetch-ort: $*" >&2
    exit 1
}

# Fails unless FILE has the pinned hash and a valid pyke build attestation.
verify() {
    local file="$1"
    local actual
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    [[ "$actual" == "$ORT_SHA256" ]] \
        || die "SHA-256 mismatch: expected $ORT_SHA256, got $actual"

    gh attestation verify --help >/dev/null 2>&1 \
        || die "gh with the 'attestation' command (>= 2.49) is required"
    gh attestation verify "$file" --owner "$ATTESTATION_OWNER" >/dev/null \
        || die "attestation verification failed for owner $ATTESTATION_OWNER"
}

if [[ "${1:-}" == "--verify" ]]; then
    [[ -n "${2:-}" ]] || die "usage: $0 --verify FILE"
    verify "$2"
    echo "fetch-ort: $2 verified"
    exit 0
fi

# The stamp records the verified archive hash and the hash of the library
# extracted from it. A copy restored from a cache is used only when both still
# match, so a swapped library is fetched and verified again.
lib_sha256() {
    sha256sum "$LIB" | cut -d' ' -f1
}

if [[ -f "$LIB" && -f "$STAMP" && "$(cat "$STAMP")" == "$ORT_SHA256 $(lib_sha256)" ]]; then
    echo "fetch-ort: ONNX Runtime $ORT_VERSION already verified in $DEST_DIR"
    exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ARCHIVE="$TMP_DIR/onnxruntime.tar.lzma2"

echo "fetch-ort: downloading ONNX Runtime $ORT_VERSION..."
curl -sSfL --retry 3 -o "$ARCHIVE" "$ORT_URL"
verify "$ARCHIVE"

# Extract into a temp directory first, so a failed extraction never leaves a
# library behind that the stamp check could mistake for a verified one.
mkdir -p "$TMP_DIR/out"
xz --format=raw --lzma2=dict=64MiB -dc "$ARCHIVE" | tar -x -C "$TMP_DIR/out"
[[ -f "$TMP_DIR/out/libonnxruntime.a" ]] || die "archive holds no libonnxruntime.a"

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
mv "$TMP_DIR/out/libonnxruntime.a" "$LIB"
echo "$ORT_SHA256 $(lib_sha256)" > "$STAMP"
echo "fetch-ort: ONNX Runtime $ORT_VERSION verified and extracted to $DEST_DIR"
