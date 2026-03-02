
---

# Keypad Lock FSM (Rust)

A memory-safe, allocation-free, side-effect-free finite state machine (FSM) modeling a secure embedded keypad lock.

This project demonstrates disciplined state modeling, secret hygiene, and hardware-boundary separation suitable for embedded or IoT deployments.

---

## Design Goals

* No heap allocation
* No `unsafe`
* Deterministic, pure transitions
* Explicit hardware side-effects
* Secret memory hygiene
* Fail-closed recovery from persistence

---

## Core Architecture

The system is modeled as a pure state transition:

```text
Event + CurrentState -> (NextState, Actions)
```

The FSM itself performs **no I/O**.

All hardware effects (door lock, alarm, display updates) are emitted as explicit `Action` values and must be executed by an external driver.

This separation enables:

* Deterministic testing
* Platform independence
* Embedded-friendly integration
* Replayable simulation

---

## Security Characteristics

* Bounded passcode buffer (max 6 digits)
* Secret memory zeroized on clear and drop (`zeroize`)
* Fixed-iteration passcode comparison (constant-time style)
* Lockout after configurable failed attempts
* Secure-fail MFA stub (compile-time gated feature)
* Strict validation of persisted state to prevent impossible restores
* Diff-based output emission (prevents action spam and hardware jitter)
* Fail-closed posture on restore

---

## Optional MFA (Feature: `acoustic_unlock`)

When enabled:

```bash
cargo build --features acoustic_unlock
```

Correct PIN entry transitions to `PendingAudio`, requiring a second factor.

The included verifier is intentionally a secure-fail stub:

> Production systems must use authenticated cryptographic verification.

---

## Threat Model

Designed for embedded lock scenarios where:

* Offline brute-force attempts are possible
* Memory disclosure risk exists (mitigated via zeroization)
* Persistence may be tampered with (validated strictly on restore)
* Timing attacks are low risk but mitigated at the comparison layer

---

## Testing

Run all tests:

```bash
cargo test
```

---

## Why This Exists

This project is intentionally over-engineered for a “keypad lock” in order to demonstrate:

* Robust finite state machine design
* Embedded-friendly Rust patterns
* Secret handling discipline
* Misuse-resistant persistence modeling
* Clear separation of logic and side effects

---

## License

Apache-2.0

---
