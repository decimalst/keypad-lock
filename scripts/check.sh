#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
for features in '' '--all-features'; do
  # Intentional expansion: an empty string supplies no feature flag.
  cargo clippy --locked --all-targets $features -- -D warnings
  cargo test --locked $features
  cargo test --locked --release $features
  cargo check --locked --lib --target thumbv7em-none-eabihf $features
done
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features
