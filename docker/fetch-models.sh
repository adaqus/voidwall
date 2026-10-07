#!/usr/bin/env bash
#
# Fetches the models the dev stack's guards run and verifies each file before
# docker compose mounts it. The files land in `models/`, which is gitignored;
# the image ships no model.
#
# Pinned to Wolf Defender Prompt-Injection Detector Small v2, revision
# bcab2eff97bcabd7227849639e2d0d7a61b46c92: the fp32 ONNX export, its
# tokenizer, and its Apache-2.0 LICENSE. The repository's `l2/` directory is
# GPL-3.0-only or commercial and is never fetched. The repository is public, so
# no Hugging Face token is needed.
#
# Needs: curl and sha256sum.
#
# Usage:
#   docker/fetch-models.sh              # fetch and verify (skips matching files)
#
set -euo pipefail

WOLF_REPO="patronus-studio/wolf-defender-prompt-injection-small"
WOLF_REVISION="bcab2eff97bcabd7227849639e2d0d7a61b46c92"
WOLF_URL="https://huggingface.co/$WOLF_REPO/resolve/$WOLF_REVISION"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODELS_DIR="$PROJECT_DIR/models"
WOLF_DIR="$MODELS_DIR/wolf-small"

die() {
    echo "fetch-models: $*" >&2
    exit 1
}

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

mkdir -p "$WOLF_DIR"
# The temp directory sits next to the destination, so the final `mv` is a
# rename and a failed download never leaves a partial file under its real name.
TMP_DIR="$(mktemp -d "$MODELS_DIR/.fetch.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# Downloads URL to DEST unless DEST already has the pinned hash.
fetch() {
    local url="$1" dest="$2" expected="$3"
    local name="${dest#"$PROJECT_DIR"/}"

    if [[ -f "$dest" && "$(sha256 "$dest")" == "$expected" ]]; then
        echo "fetch-models: $name already verified"
        return
    fi

    echo "fetch-models: downloading $name..."
    local tmp="$TMP_DIR/$(basename "$dest")"
    curl -sSfL --retry 3 -o "$tmp" "$url" || die "download failed for $name"
    local actual
    actual="$(sha256 "$tmp")"
    [[ "$actual" == "$expected" ]] \
        || die "SHA-256 mismatch for $name: expected $expected, got $actual"
    mv "$tmp" "$dest"
    echo "fetch-models: $name verified"
}

fetch "$WOLF_URL/onnx/onnx_fp32/model.onnx" "$WOLF_DIR/model.onnx" \
    "49455de2407c134dd136c64ca38d67ca17f8426e99fe5c6e286d69af9932993f"
fetch "$WOLF_URL/tokenizer.json" "$WOLF_DIR/tokenizer.json" \
    "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c"
fetch "$WOLF_URL/LICENSE" "$WOLF_DIR/LICENSE" \
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
