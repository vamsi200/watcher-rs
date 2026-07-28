#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

run_userspace() {
  RUST_LOG=debug cargo run \
    --manifest-path "$ROOT/Cargo.toml" \
    --config 'target."cfg(all())".runner="sudo -E"'
}

main() {
  echo "[INFO] Building and running program..."
  run_userspace
}

main "$@"
