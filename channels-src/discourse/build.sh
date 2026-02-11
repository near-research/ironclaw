#!/usr/bin/env bash
# Build the Discourse channel WASM component
#
# Prerequisites:
#   - Rust with wasm32-wasip2 target: rustup target add wasm32-wasip2
#   - wasm-tools for component creation: cargo install wasm-tools
#
# Output:
#   - discourse.wasm - WASM component ready for deployment
#   - discourse.capabilities.json - Capabilities file (copy alongside .wasm)
#
# NOTE: discourse.capabilities.json is configured for discuss.near.vote.
# Edit the http.allowlist host if deploying to a different Discourse instance.

set -euo pipefail

cd "$(dirname "$0")"

echo "Building Discourse channel WASM component..."

# Build the WASM module
cargo build --release --target wasm32-wasip2

# Convert to component model (if not already a component)
# wasm-tools component new is idempotent on components
WASM_PATH="target/wasm32-wasip2/release/discourse_channel.wasm"

if [ -f "$WASM_PATH" ]; then
    # Create component if needed
    wasm-tools component new "$WASM_PATH" -o discourse.wasm 2>/dev/null || cp "$WASM_PATH" discourse.wasm

    # Optimize the component
    wasm-tools strip discourse.wasm -o discourse.wasm

    echo "Built: discourse.wasm ($(du -h discourse.wasm | cut -f1))"
    echo ""
    echo "Deploy:"
    echo "  cp discourse.wasm discourse.capabilities.json ~/.ironclaw/channels/"
    echo ""
    echo "NOTE: discourse.capabilities.json is configured for discuss.near.vote"
    echo "      Edit the http.allowlist host if deploying to a different instance"
    echo ""
    echo "TIP:  Set config.bot_username to your discourse_api_username value"
    echo "      for faster loop prevention (skips posts from the bot user)"
else
    echo "Error: WASM output not found at $WASM_PATH"
    exit 1
fi
