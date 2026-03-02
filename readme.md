# Keypad Lock FSM (Rust)

A memory-safe, side-effect-free finite state machine (FSM) modeling a secure keypad lock system in Rust.

This project demonstrates:

* Type-safe digit representation
* Bounded passcode buffers
* Zeroized secret memory (`zeroize`)
* Branchless passcode comparison
* Lockout protection against brute-force attempts
* Optional compile-time gated MFA (audio challenge)
* Pure state transitions returning explicit hardware actions

---

## Build

```bash
cargo build
```

## Run

```bash
cargo run
```

---

## Optional Feature: Acoustic MFA

Compile with:

```bash
cargo build --features acoustic_unlock
```

This enables a second authentication factor after correct PIN entry.

---

## Architecture

The system is modeled as a pure state machine:

```
Event + CurrentState -> (NextState, Actions)
```

### States

* `Setup`
* `Locked`
* `Lockout`
* `PendingAudio` (optional MFA)
* `Unlocked`
* `Alarm`

All hardware side-effects (door control, alarm, display) are emitted as `Action` values and must be handled externally.

---

## Security Notes

* Passcodes are stored in bounded buffers.
* Memory is zeroized on clear and drop.
* Passcode comparison avoids early-return branching.
* Lockout activates after 3 failed attempts.
* MFA path is compile-time gated and defaults to secure failure.

---

## Threat Model

Designed for embedded / IoT lock scenarios where:

* Offline brute-force is possible
* Timing attacks are low risk but mitigated
* Memory disclosure risk is reduced via zeroization
* MFA may be required depending on deployment

---

## License

MIT
