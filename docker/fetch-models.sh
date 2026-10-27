#!/usr/bin/env bash
#
# Fetches the default models and verifies each file. The files land in
# `models/`, which is gitignored. The image build copies them in, and the dev
# stack mounts its own copies over them.
#
# Pinned to Wolf Defender Prompt-Injection Detector Small v2, revision
# bcab2eff97bcabd7227849639e2d0d7a61b46c92: the fp32 ONNX export, its
# tokenizer, and its Apache-2.0 LICENSE. The repository's `l2/` directory is
# GPL-3.0-only or commercial and is never fetched.
#
# Pinned to bards.ai's EU PII anonimization multilang v2, revision
# 5e61416e77675881185767fc0c67759d48b35592: the INT8 ONNX export, its tokenizer,
# and its config.json (the source of id2label). The model card declares
# Apache-2.0, but the repository has no LICENSE file, so this script writes one:
# the source and revision, then the Apache-2.0 text of this repository's LICENSE,
# which is checked against the canonical text first.
#
# Both repositories are public, so no Hugging Face token is needed.
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

BARDS_REPO="bardsai/eu-pii-anonimization-multilang-v2"
BARDS_REVISION="5e61416e77675881185767fc0c67759d48b35592"
BARDS_URL="https://huggingface.co/$BARDS_REPO/resolve/$BARDS_REVISION"

# The SHA-256 of the canonical Apache License 2.0 text, as apache.org serves it.
APACHE_2_SHA256="cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODELS_DIR="$PROJECT_DIR/models"
WOLF_DIR="$MODELS_DIR/wolf-small"
BARDS_DIR="$MODELS_DIR/bards-v2"

die() {
    echo "fetch-models: $*" >&2
    exit 1
}

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

mkdir -p "$WOLF_DIR" "$BARDS_DIR/onnx"
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

fetch "$BARDS_URL/onnx/model_quantized.onnx" "$BARDS_DIR/onnx/model_quantized.onnx" \
    "1ee975af537a3ae507769703c03fc83880cce7e2706bc6d2dc1fd9db861acfa1"
fetch "$BARDS_URL/tokenizer.json" "$BARDS_DIR/tokenizer.json" \
    "609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f"
fetch "$BARDS_URL/config.json" "$BARDS_DIR/config.json" \
    "94805ed3a9b851a0a5c49d85c4e2dada1fe57d84838cfca8cddfca5aa53acffa"

# The model's LICENSE: written, never downloaded, and replaced only when it differs.
[[ "$(sha256 "$PROJECT_DIR/LICENSE")" == "$APACHE_2_SHA256" ]] \
    || die "LICENSE is not the Apache-2.0 text; cannot write models/bards-v2/LICENSE"
{
    echo "Source: https://huggingface.co/$BARDS_REPO"
    echo "Revision: $BARDS_REVISION"
    echo "License: Apache-2.0, as declared by the model card. The repository has no"
    echo "LICENSE file; the text below is the Apache License 2.0."
    echo
    cat "$PROJECT_DIR/LICENSE"
} > "$TMP_DIR/LICENSE"
if cmp -s "$TMP_DIR/LICENSE" "$BARDS_DIR/LICENSE"; then
    echo "fetch-models: models/bards-v2/LICENSE up to date"
else
    mv "$TMP_DIR/LICENSE" "$BARDS_DIR/LICENSE"
    echo "fetch-models: models/bards-v2/LICENSE written"
fi
