# Keypad Lock FSM (Rust)

A memory-safe, side-effect-free finite state machine (FSM) modeling a secure keypad lock system in Rust.

This project demonstrates:


- Type-safe digit representation (`Digit`)
- Bounded passcode buffers (`PasscodeBuffer`, max 6 digits)
- Zeroized secret memory (`zeroize`)
- Branchless (fixed-iteration) passcode comparison
- Lockout protection against brute-force attempts
- Optional compile-time gated MFA (acoustic challenge)
- Pure state transitions returning explicit hardware actions

---

## Build

```bash
cargo build
```

## Run (demo binary)

Compile / test with:

```bash
cargo build --features acoustic_unlock
cargo test  --features acoustic_unlock
```

When enabled, a correct PIN transitions to `PendingAudio`, where a second factor must be verified.

> Note: the `verify_audio_challenge` implementation is intentionally a **secure-fail stub**.
> In a real system, the MFA verifier must be backed by authenticated cryptographic proof.

---

## Architecture

The system is modeled as a pure state machine:

<<<<<<< HEAD
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
=======
- Passcodes are stored in bounded buffers.
- Secret memory is zeroized on clear and on drop.
- Passcode comparison avoids early-return branching by comparing a fixed-size buffer.
- Lockout activates after 3 failed attempts.
- Empty "Enter" submissions are ignored to prevent trivial lockout-by-spam.
- The MFA path is compile-time gated and defaults to secure failure.

---

## Testing

Run unit + integration tests:

```bash
cargo test
```

---

## License

Apache-2.0 (see `LICENSE`).
