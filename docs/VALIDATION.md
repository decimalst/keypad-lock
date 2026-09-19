# Validation record

Measured locally on 2026-09-18, Apple Silicon macOS, Rust 1.98.1 (2024 edition), cargo-llvm-cov 0.9.1. Baseline: `915a195` on `main`. These are recorded local results; GitHub's workflow page is the authority for hosted CI outcomes.

## Review findings addressed

| Original behavior | Change and regression evidence |
| --- | --- |
| Input beyond six digits was dropped, so a correct six-digit prefix still authenticated | Overflow invalidates the submission; regression covers both setup and authentication. |
| Restored non-setup states could contain PINs shorter than enrollment policy | Validate length and digit content; exhaustively exercise all 256 encoded lengths. |
| Intrusion alarm expiry reset failed attempts | Preserve attempts in the alarm state and v3 snapshot; test alarm plus reboot followed by a third failure. |
| Startup and restore assumed outputs were already applied | Explicit complete-output synchronization; tests cover every hardware output. |
| Unprimed restore assumed the door was closed | Inhibit timed relock until a live closed reading; test an extreme elapsed duration. |
| All-features baseline had two failing tests | Feature-aware default unlock tests plus pending-audio timeout, intrusion and denial regressions. |
| README path differed in case from package metadata | Rename to `README.md`; verify a packaged crate builds. |
| Embedded-friendly claim had no `no_std` build or CI | Disable dependency default features; compile the library for `thumbv7em-none-eabihf`. |

The original default suite passed 13 tests; the original all-features suite passed 13 and failed 2.

## Final local checks

- **36 tests with default features; 37 with all features**, including the executable tests and one doctest. Both debug and release profiles pass.
- Independent model: **7,776 histories × 5 prefixes** per feature configuration. Checks modes, retry counts, bolt posture and alarm output after every operation.
- Strict Clippy in both configurations, formatting, documentation with warnings denied, and embedded ARM compilation in both configurations pass.
- `cargo package --offline --locked --allow-dirty` builds the packaged crate successfully. This verifies packaging; it does not publish a crate.
- RustSec audit: **0 reported vulnerabilities, no warnings**, against 1,251 advisories; database revision `2b34578f89884736e0fcbd42f7ba8d6b10b4a0ce`, updated 2026-09-18. This is a dated advisory check, not a security certification.
- Architecture PNG and demo PNG were visually inspected; the animation is generated from the exact CLI transcript checked by integration tests.

## Coverage

Both feature configurations were measured **separately**, without excluding library or executable source. Integration-test files and dependency source are outside the source-coverage denominator; the in-file secret-buffer unit test is included in `src/lib.rs`. Machine-readable counts are in [coverage-summary.json](coverage-summary.json).

| Configuration | Library lines | Demo lines | All source lines | Source functions |
| --- | ---: | ---: | ---: | ---: |
| Default | 547 / 548 · 99.82% | 72 / 72 · 100% | 619 / 620 · **99.84%** | 49 / 49 · **100%** |
| Acoustic | 627 / 628 · 99.84% | 70 / 70 · 100% | 697 / 698 · **99.86%** | 49 / 49 · **100%** |

The report retains one unexecuted source-line count in each configuration. We do not claim 100% line coverage. Branch and MC/DC coverage were not collected. LLVM region coverage is 99.58% / 99.47%; generic-instantiation coverage is a different metric and is not 100%. CI enforces a 99% line floor in each configuration.

Reproduce the measurements using the commands in [CONTRIBUTING.md](../CONTRIBUTING.md). Core and demo source have no coverage exclusions. Hardware, storage cryptography, power-loss behavior, timing side channels and physical actuator safety require separate integration testing.

## Toolchain provenance

[Rust's official release index](https://blog.rust-lang.org/releases/) listed Rust 1.98.1 as the current stable release at this review. `rustup` downloaded and verified that version. The repository pins it for repeatable runs; CI also tests the moving stable channel on scheduled runs. The 2024 edition remains the current stable edition.
