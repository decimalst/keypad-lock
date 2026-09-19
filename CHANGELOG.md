# Changelog

## 0.2.0 — 2026-09-18

### Correctness and security

- Reject overlong PIN guesses instead of accepting a matching truncated prefix; require clear after overlong enrollment.
- Reject restored credentials outside the enrollment length policy and invalid PIN digits.
- Preserve failed-attempt counts through intrusion alarms and persistence.
- Add explicit full-output synchronization and conservative unprimed door recovery.
- Raise an alarm on intrusion during the optional pending-audio phase; retain unconditional audio rejection.
- Redact keypress/audio event debug output and make internal action overflow fail loudly in release builds.

### Platform and quality

- Rust 2024, pinned Rust 1.98.1, updated dependencies, and a real `no_std` library with default dependency features disabled.
- Add secret-free `mode()` inspection, boundary regressions, independent policy-model histories and executable transcript tests.
- Add cross-platform CI, optimized tests, embedded compilation, coverage gates, advisory auditing and Dependabot.
- Replace the minimal host executable with a repeatable demonstration; add architecture images, an animated transcript, and integration guidance.
- Fix the README filename to match package metadata on case-sensitive filesystems.

### Migration from 0.1.0

Persistence version changes from **2 to 3**. Old snapshots return `None`; migrate them only through an authenticated, authorized adapter procedure. Never silently fall back to enrollment. Partial setup input is now transient and is discarded by snapshots. Alarm snapshots may retain prior failed attempts. `restore_primed_with` returns complete output synchronization rather than only differences; apply all returned actions. `restore_with` no longer assumes a closed door for an unlocked snapshot.
