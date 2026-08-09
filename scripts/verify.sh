#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
cargo run --quiet -p compute-commons -- demo | grep '"verification": "EXACT_MATCH"'
if git grep -nEI '(BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})' -- ':!scripts/verify.sh'; then
  echo "possible secret detected" >&2
  exit 1
fi

