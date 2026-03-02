//! # Keypad Lock FSM
//!
//! A memory-safe, side-effect-free finite state machine (FSM) modeling a secure keypad lock.
//!
//! The core transition is pure:
//!
//! ```text
//! Event + CurrentState -> (NextState, Actions)
//! ```
//!
//! All hardware side-effects are represented as `Action` values and must be performed externally.

#![forbid(unsafe_code)]

use std::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum passcode length accepted during setup.
pub const MIN_PASSCODE_LEN: u8 = 3;
/// Maximum passcode length.
pub const MAX_PASSCODE_LEN: usize = 6;
/// Number of failed attempts before entering lockout.
pub const LOCKOUT_THRESHOLD: u8 = 3;

/// Duration of the lockout penalty period.
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(30);
/// How long the door stays unlocked before auto re-lock.
pub const UNLOCKED_DURATION: Duration = Duration::from_secs(10);
/// How long the alarm remains active before resetting back to `Locked`.
pub const ALARM_DURATION: Duration = Duration::from_secs(5);

/// MFA timeout when `acoustic_unlock` is enabled.
#[cfg(feature = "acoustic_unlock")]
pub const MFA_TIMEOUT: Duration = Duration::from_secs(5);

/// A single keypad digit (0-9).
///
/// The inner value is private so callers must go through `Digit::new` or `TryFrom<u8>`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digit(u8);

impl Digit {
    /// Construct a digit from an integer in the range 0..=9.
    pub fn new(val: u8) -> Option<Self> {
        (val <= 9).then_some(Self(val))
    }

    /// Extract the numeric value (0..=9).
    pub fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Digit {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Digit::new(value).ok_or(())
    }
}

/// A bounded buffer holding a passcode.
///
/// This type is `ZeroizeOnDrop` and also supports explicit clearing.
///
/// Notes:
/// - The buffer uses a fixed capacity (`MAX_PASSCODE_LEN`).
/// - Comparisons are performed in a branchless, fixed-iteration manner.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasscodeBuffer {
    digits: [u8; MAX_PASSCODE_LEN],
    len: u8,
}

impl Default for PasscodeBuffer {
    fn default() -> Self {
        Self {
            digits: [0u8; MAX_PASSCODE_LEN],
            len: 0,
        }
    }
}

impl core::fmt::Debug for PasscodeBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact secret material in debug output.
        f.debug_struct("PasscodeBuffer")
            .field("len", &self.len)
            .field("digits", &"[REDACTED]")
            .finish()
    }
}

impl PasscodeBuffer {
    /// Push a digit, returning whether it was accepted.
    ///
    /// If the buffer is full, this is a no-op and returns `false`.
    pub fn push(&mut self, d: Digit) -> bool {
        let idx = self.len as usize;
        if idx < MAX_PASSCODE_LEN {
            self.digits[idx] = d.value();
            self.len += 1;
            true
        } else {
            false
        }
    }

    /// Zeroize all digits and reset the length to 0.
    pub fn clear(&mut self) {
        self.digits.zeroize();
        self.len = 0;
    }

    /// Current number of stored digits.
    pub fn len(&self) -> u8 {
        self.len
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the buffer is at capacity.
    pub fn is_full(&self) -> bool {
        self.len as usize >= MAX_PASSCODE_LEN
    }

    /// Constant-time equality of digits + length.
    ///
    /// This runs a fixed number of iterations (always `MAX_PASSCODE_LEN`).
    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;

        for i in 0..MAX_PASSCODE_LEN {
            diff |= self.digits[i] ^ other.digits[i];
        }

        diff |= self.len ^ other.len;

        diff == 0
    }

    /// Branchless digit + length compare, requiring non-empty input.
    ///
    /// Note: For strong cross-platform constant-time guarantees across optimizers,
    /// consider a vetted crate (e.g., `subtle`), but this is a solid baseline.
    pub fn matches(&self, other: &Self) -> bool {
        let eq = self.constant_time_eq(other);
        let non_empty = self.len != 0;
        eq && non_empty
    }
}

impl PartialEq for PasscodeBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for PasscodeBuffer {}

/// External input to the FSM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A keypad digit was pressed.
    Keypress(Digit),
    /// The user pressed an "enter" / "submit" key.
    Enter,
    /// The user pressed a clear/backspace key.
    Clear,
    /// Passage of time.
    TimerTick(Duration),

    /// Optional MFA: the measured audio frequency (Hz) from an external sensor.
    #[cfg(feature = "acoustic_unlock")]
    AudioFrequency(u32),
}

/// Hardware effects to perform outside the FSM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Update the display with how many digits have been entered.
    UpdateDisplayLen(u8),
    /// Enable/disable alarm.
    SoundAlarm(bool),
    /// Control the door lock solenoid.
    ///
    /// `true` = locked, `false` = unlocked.
    SetDoorLock(bool),
}

/// FSM state.
#[derive(Debug, PartialEq, Eq)]
pub enum SecurityState {
    /// Initial setup: choose a passcode.
    Setup { buffer: PasscodeBuffer },

    /// Normal locked mode.
    Locked {
        passcode: PasscodeBuffer,
        guess: PasscodeBuffer,
        failed_attempts: u8,
    },

    /// Penalty box after too many failed attempts.
    Lockout { passcode: PasscodeBuffer, elapsed: Duration },

    /// Optional MFA step after correct PIN.
    #[cfg(feature = "acoustic_unlock")]
    PendingAudio { passcode: PasscodeBuffer, elapsed: Duration },

    /// Door is unlocked temporarily.
    Unlocked { passcode: PasscodeBuffer, elapsed: Duration },

    /// Alarm state.
    Alarm { passcode: PasscodeBuffer, elapsed: Duration },
}

impl Default for SecurityState {
    fn default() -> Self {
        SecurityState::Setup {
            buffer: PasscodeBuffer::default(),
        }
    }
}

fn add_duration_saturating(a: Duration, b: Duration) -> Duration {
    // Hardening: prevent panic on overflow in adversarial / fuzz scenarios.
    a.checked_add(b).unwrap_or(Duration::MAX)
}

impl SecurityState {
    /// Pure state transition.
    ///
    /// Returns the next state plus the `Action`s required to make hardware match the new state.
    #[must_use]
    pub fn next(self, event: Event) -> (Self, Vec<Action>) {
        use Event::*;
        use SecurityState::*;

        match (self, event) {
            // --- MODE 1: SETUP ---
            (Setup { mut buffer }, Keypress(d)) => {
                buffer.push(d);
                let len = buffer.len();
                (Setup { buffer }, vec![Action::UpdateDisplayLen(len)])
            }
            (Setup { mut buffer }, Clear) => {
                buffer.clear();
                (Setup { buffer }, vec![Action::UpdateDisplayLen(0)])
            }
            (Setup { buffer }, Enter) if buffer.len() >= MIN_PASSCODE_LEN => {
                let actions = vec![Action::UpdateDisplayLen(0), Action::SetDoorLock(true)];
                (
                    Locked {
                        passcode: buffer,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    },
                    actions,
                )
            }

            // --- MODE 2: LOCKED ---
            (Locked {
                passcode,
                mut guess,
                failed_attempts,
            }, Keypress(d)) => {
                guess.push(d);
                let len = guess.len();
                (
                    Locked {
                        passcode,
                        guess,
                        failed_attempts,
                    },
                    vec![Action::UpdateDisplayLen(len)],
                )
            }
            (Locked {
                passcode,
                mut guess,
                failed_attempts,
            }, Clear) => {
                guess.clear();
                (
                    Locked {
                        passcode,
                        guess,
                        failed_attempts,
                    },
                    vec![Action::UpdateDisplayLen(0)],
                )
            }
            (Locked {
                passcode,
                mut guess,
                failed_attempts,
            }, Enter) => {
                // Usability hardening: don't count empty submits as a failed attempt.
                // This avoids a trivial DoS-by-spam-Enter lockout.
                if guess.is_empty() {
                    return (
                        Locked {
                            passcode,
                            guess,
                            failed_attempts,
                        },
                        vec![Action::UpdateDisplayLen(0)],
                    );
                }

                let ok = guess.matches(&passcode);
                guess.clear(); // zeroize user input immediately

                if ok {
                    #[cfg(feature = "acoustic_unlock")]
                    {
                        (
                            PendingAudio {
                                passcode,
                                elapsed: Duration::ZERO,
                            },
                            vec![Action::UpdateDisplayLen(0), Action::SetDoorLock(true)],
                        )
                    }

                    #[cfg(not(feature = "acoustic_unlock"))]
                    {
                        (
                            Unlocked {
                                passcode,
                                elapsed: Duration::ZERO,
                            },
                            vec![Action::SetDoorLock(false), Action::UpdateDisplayLen(0)],
                        )
                    }
                } else {
                    let new_attempts = failed_attempts.saturating_add(1);

                    if new_attempts >= LOCKOUT_THRESHOLD {
                        (
                            Lockout {
                                passcode,
                                elapsed: Duration::ZERO,
                            },
                            vec![
                                Action::UpdateDisplayLen(0),
                                Action::SoundAlarm(true),
                                Action::SetDoorLock(true),
                            ],
                        )
                    } else {
                        (
                            Locked {
                                passcode,
                                guess,
                                failed_attempts: new_attempts,
                            },
                            vec![Action::UpdateDisplayLen(0)],
                        )
                    }
                }
            }

            // --- MODE 3: LOCKOUT (Anti-Brute Force) ---
            (Lockout { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(elapsed, dt);
                if new_elapsed >= LOCKOUT_DURATION {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![
                            Action::SoundAlarm(false),
                            Action::SetDoorLock(true),
                            Action::UpdateDisplayLen(0),
                        ],
                    )
                } else {
                    // Idempotent assertions during lockout.
                    (
                        Lockout {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        vec![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }

            // --- MODE 4: PENDING AUDIO (MFA Challenge) ---
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed: _ }, AudioFrequency(freq)) => {
                if verify_audio_challenge(&passcode, freq) {
                    (
                        Unlocked {
                            passcode,
                            elapsed: Duration::ZERO,
                        },
                        vec![Action::SetDoorLock(false)],
                    )
                } else {
                    (
                        Alarm {
                            passcode,
                            elapsed: Duration::ZERO,
                        },
                        vec![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(elapsed, dt);
                if new_elapsed >= MFA_TIMEOUT {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                    )
                } else {
                    (
                        PendingAudio {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        vec![Action::SetDoorLock(true)],
                    )
                }
            }

            // --- MODE 5: UNLOCKED ---
            (Unlocked { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(elapsed, dt);
                if new_elapsed >= UNLOCKED_DURATION {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                    )
                } else {
                    (
                        Unlocked {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        vec![Action::SetDoorLock(false)],
                    )
                }
            }

            // --- MODE 6: ALARM ---
            (Alarm { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(elapsed, dt);
                if new_elapsed >= ALARM_DURATION {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![
                            Action::SoundAlarm(false),
                            Action::SetDoorLock(true),
                            Action::UpdateDisplayLen(0),
                        ],
                    )
                } else {
                    (
                        Alarm {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        vec![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }

            // Catch-all: drop invalid inputs (e.g., keypresses during lockout)
            (state, _) => (state, vec![]),
        }
    }
}

// NOTE: Never return true without authenticated cryptographic proof.
// This must NOT be a simple "freq near passcode" logic in production.
#[cfg(feature = "acoustic_unlock")]
fn verify_audio_challenge(_p: &PasscodeBuffer, _freq: u32) -> bool {
    false // Default to secure failure for this stub.
}
