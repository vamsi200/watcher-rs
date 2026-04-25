#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

build_ebpf() {
  cargo +nightly build \
    -Z build-std=core \
    --target bpfel-unknown-none \
    --release \
    --manifest-path "$ROOT/watcher-rs-ebpf/Cargo.toml"
}

run_userspace() {
  RUST_LOG=info cargo run \
    --manifest-path "$ROOT/Cargo.toml" \
    --config 'target."cfg(all())".runner="sudo -E"'
}

main() {
  echo "[INFO] Building and program..."
  build_ebpf
  run_userspace
}

main "$@"
