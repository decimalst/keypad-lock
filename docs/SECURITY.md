# Integration and security boundaries

This repository is a lock-policy model and host demonstration. It does not ship a board driver, cryptographic storage implementation, authenticated second factor, or safety certification.

## What the core enforces

- PIN buffers are bounded. Overflow invalidates a submitted guess until clear or submission; it never authenticates a prefix. Enrollment requires clear after overflow.
- Empty Enter does not consume attempts; incorrect non-empty submissions do. Intrusion alarms preserve the retry budget.
- Lockout ignores keypad input and expires only as elapsed-time events advance.
- Automatic relocking of an unlocked state waits for a closed door reading.
- Arithmetic saturates at extreme durations. Internal action overflow panics in both debug and release instead of dropping a hardware command silently.
- Secret buffers zeroize on clear/drop; debug output for state and input events redacts digits. Comparison uses `subtle` across the fixed digit array and length. This is not a proof of constant-time behavior on every compiler and device.

## Adapter obligations

1. **Authorize enrollment and recovery.** `default()` begins Setup. After storage corruption or failed authentication of a snapshot, inhibit the device and require an authorized recovery path; do not call `default()` as an unattended fallback.
2. **Synchronize the executor.** Apply `output_actions()` for a fresh state or the complete action list returned by `restore_primed_with`. During ordinary operation apply actions in order. The core records desired outputs, not hardware acknowledgements; missed actions must be retried or followed by resynchronization.
3. **Protect the complete snapshot.** Use authenticated encryption for the PIN and authenticated metadata, with appropriate nonce/key management, atomic writes and anti-rollback storage. `PasscodeSealer` only receives PIN bytes. A forged retry count or replayed older snapshot can defeat rate limiting if the adapter fails to protect it. The test fixtures use plaintext solely to inspect invariants.
4. **Persist security transitions reliably.** Power cycling must not roll back failed attempts. Restored elapsed time does not include downtime; the adapter must define its reboot/timing policy. Snapshot v3 is deliberately incompatible with v2.
5. **Trust neither electrical input nor desired output blindly.** Debounce sensors, use monotonic timer deltas, serialize events and validate sensor/actuator faults outside the core. Negative elapsed durations cannot be represented; large positive values still depend on a trusted timer source.
6. **Implement mechanical interlocks and emergency egress.** The open-door inhibit applies to automatic relocking in `Unlocked`. Setup, locked, lockout and alarm states request a locked posture. This is not a universal physical anti-jam or life-safety interlock. Alarm timeout returns to Locked even if no new closed reading arrives; an adapter must handle a persistently open or failed sensor.
7. **Handle plaintext at the boundary.** Sealing necessarily hands raw PIN bytes to the adapter. That code must avoid logging secrets and clear its own temporary copies. Zeroization cannot guarantee erasure of every compiler/register copy or protect against a compromised device.

## Recovery semantics

`restore_primed_with` validates structural invariants, unseals the PIN, processes a live door reading and emits all three desired hardware outputs. A valid Unlocked snapshot may resume an unlocked state, and a closed door can trigger immediate relocking if its timer is already expired. The lower-level restore uses an open/unknown assumption to inhibit automatic relocking until a closed sensor event.

Alarm snapshots retain 0–2 previous failed attempts; Lockout requires exactly 3. Non-setup modes require a valid 3–6 digit credential. Setup snapshots contain no partial enrollment digits. Unsupported versions and invalid states return `None`.

## Acoustic feature

`acoustic_unlock` demonstrates a pending phase, timeout and explicit denial. It never validates audio as a second factor. All frequencies fail. Door opening during the pending phase raises an alarm. Deployments need an independently designed authenticated challenge protocol before offering MFA.

## Evidence limits

Coverage is an execution metric, not a security proof. Host tests and cross-compilation cannot validate power loss, electrical noise, physical timing, actuator jams, flash wear or secure key storage. The current validation record is in [VALIDATION.md](VALIDATION.md).
