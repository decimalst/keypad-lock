# Contributing

Use the pinned toolchain, preserve the pure-core boundary, and add behavioral regression tests for policy changes. Never log real PINs or add production credentials to examples.

Install the embedded target with `rustup target add thumbv7em-none-eabihf`, then run `bash scripts/check.sh`. Both the default and `acoustic_unlock` builds must pass; the feature intentionally rejects every audio response.

Measure coverage separately in both configurations (do not substitute `--all-features` for testing defaults):

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
cargo llvm-cov --locked --fail-under-lines 99
cargo llvm-cov --locked --all-features --fail-under-lines 99
```

For dependency auditing, install `cargo-audit` 0.22.2 with `--locked` and run `cargo audit`.

If demo behavior changes intentionally, refresh `docs/demo.txt` with `cargo run --locked --quiet` and `docs/demo-acoustic.txt` with the all-features run. Review the transcripts, rerun tests, then rebuild presentation assets with `scripts/render_assets.py` and inspect them visually. Do not refresh snapshots just to hide a failing behavior test.

Persistence-format changes require a version bump and explicit recovery/migration documentation. Structural validation is not metadata authentication.
