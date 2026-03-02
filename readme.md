# Keypad Lock FSM (Rust)

A memory-safe, side-effect-free finite state machine (FSM) modeling a secure keypad lock system in Rust.

This project demonstrates:

- Type-safe digit representation
- Bounded passcode buffers
- Zeroized secret memory (`zeroize`)
- Constant-time passcode comparison (branchless)
- Lockout protection against brute-force attempts
- Optional compile-time gated MFA (audio challenge)
- Pure state transitions returning explicit hardware actions

---

## Build

```bash
cargo build