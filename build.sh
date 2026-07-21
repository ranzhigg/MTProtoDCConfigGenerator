#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT_PATH=${1:-"$SCRIPT_DIR/build/mtproto-dc-config"}
BUILT_BINARY="$SCRIPT_DIR/target/release/mtproto-dc-config"

cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

mkdir -p "$(dirname -- "$OUTPUT_PATH")"
cp "$BUILT_BINARY" "$OUTPUT_PATH"

echo "$OUTPUT_PATH"
