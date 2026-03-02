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

use core::hint::black_box;
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

/// Max number of actions emitted by any single transition.
pub const MAX_ACTIONS: usize = 4;

/// Fixed-capacity action buffer (zero-allocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actions<const N: usize> {
    buf: [Option<Action>; N],
    len: usize,
}

impl<const N: usize> Default for Actions<N> {
    fn default() -> Self {
        Self {
            buf: core::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl<const N: usize> Actions<N> {
    pub fn push(&mut self, a: Action) -> bool {
        if self.len < N {
            self.buf[self.len] = Some(a);
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.buf[..self.len].iter().filter_map(|x| x.as_ref())
    }
}

impl<const N: usize> IntoIterator for Actions<N> {
    type Item = Action;
    type IntoIter = core::iter::FilterMap<
        core::array::IntoIter<Option<Action>, N>,
        fn(Option<Action>) -> Option<Action>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn keep(x: Option<Action>) -> Option<Action> {
            x
        }
        self.buf.into_iter().filter_map(keep as fn(_) -> _)
    }
}

impl<'a, const N: usize> IntoIterator for &'a Actions<N> {
    type Item = &'a Action;
    type IntoIter = core::iter::FilterMap<
        core::slice::Iter<'a, Option<Action>>,
        fn(&'a Option<Action>) -> Option<&'a Action>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn keep<'a>(x: &'a Option<Action>) -> Option<&'a Action> {
            x.as_ref()
        }
        self.buf[..self.len].iter().filter_map(keep as fn(_) -> _)
    }
}

macro_rules! actions {
    () => {
        Actions::<MAX_ACTIONS>::default()
    };
    ($($a:expr),+ $(,)?) => {{
        let mut out = Actions::<MAX_ACTIONS>::default();
        $(
            let _ = out.push($a);
        )+
        out
    }};
}

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
    ///
    /// Hardening: `black_box` discourages LLVM from proving facts about `diff`
    /// and “helpfully” reintroducing data-dependent early-exit behavior.
    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;

        for i in 0..MAX_PASSCODE_LEN {
            diff |= self.digits[i] ^ other.digits[i];
            diff = black_box(diff);
        }

        diff |= self.len ^ other.len;
        diff = black_box(diff);

        black_box(diff) == 0
    }

    /// Branchless digit + length compare, requiring non-empty input.
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

/// Door state as observed by a physical sensor (e.g., magnetic reed switch).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DoorPhysicalState {
    Open,
    Closed,
}

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

    /// Door sensor changed state (debounced/edge-detected externally).
    DoorSensorChanged(DoorPhysicalState),

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

    /// Door is unlocked temporarily (tracks door physical state to avoid “locking open”).
    Unlocked {
        passcode: PasscodeBuffer,
        elapsed: Duration,
        door: DoorPhysicalState,
    },

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

/// A compact, validation-friendly snapshot of durable state for NVRAM persistence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PersistedState {
    pub version: u8,
    pub mode: PersistedMode,
    pub passcode: PersistedPasscode,
    pub failed_attempts: u8,
    pub elapsed_ms: u32,
}

/// Durable mode tag for persistence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PersistedMode {
    Setup,
    Locked,
    Lockout,
    #[cfg(feature = "acoustic_unlock")]
    PendingAudio,
    Unlocked,
    Alarm,
}

/// Durable passcode representation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PersistedPasscode {
    pub digits: [u8; MAX_PASSCODE_LEN],
    pub len: u8,
}

impl PersistedPasscode {
    fn validate(&self) -> bool {
        (self.len as usize) <= MAX_PASSCODE_LEN && self.digits.iter().all(|d| *d <= 9)
    }

    fn to_buffer(&self) -> Option<PasscodeBuffer> {
        if !self.validate() {
            return None;
        }

        let mut buf = PasscodeBuffer::default();
        let limit = MAX_PASSCODE_LEN.min(self.len as usize);

        for i in 0..limit {
            let v = *self.digits.get(i)?;
            let d = Digit::new(v)?;
            buf.push(d);
        }

        Some(buf)
    }

    fn from_buffer(buf: &PasscodeBuffer) -> Self {
        Self {
            digits: buf.digits,
            len: buf.len,
        }
    }
}

impl PersistedState {
    pub const VERSION: u8 = 1;

    /// Validate invariants before attempting to restore.
    pub fn validate(&self) -> bool {
        self.version == Self::VERSION
            && self.passcode.validate()
            && self.failed_attempts <= LOCKOUT_THRESHOLD
    }
}

impl SecurityState {
    /// Create a persistence snapshot suitable for writing to EEPROM/NVRAM.
    #[must_use]
    pub fn snapshot(&self) -> PersistedState {
        let (mode, passcode, failed_attempts, elapsed) = match self {
            SecurityState::Setup { buffer } => (
                PersistedMode::Setup,
                PersistedPasscode::from_buffer(buffer),
                0,
                Duration::ZERO,
            ),
            SecurityState::Locked {
                passcode,
                guess: _,
                failed_attempts,
            } => (
                PersistedMode::Locked,
                PersistedPasscode::from_buffer(passcode),
                *failed_attempts,
                Duration::ZERO,
            ),
            SecurityState::Lockout { passcode, elapsed } => (
                PersistedMode::Lockout,
                PersistedPasscode::from_buffer(passcode),
                LOCKOUT_THRESHOLD,
                *elapsed,
            ),
            #[cfg(feature = "acoustic_unlock")]
            SecurityState::PendingAudio { passcode, elapsed } => (
                PersistedMode::PendingAudio,
                PersistedPasscode::from_buffer(passcode),
                0,
                *elapsed,
            ),
            SecurityState::Unlocked { passcode, elapsed, .. } => (
                PersistedMode::Unlocked,
                PersistedPasscode::from_buffer(passcode),
                0,
                *elapsed,
            ),
            SecurityState::Alarm { passcode, elapsed } => (
                PersistedMode::Alarm,
                PersistedPasscode::from_buffer(passcode),
                0,
                *elapsed,
            ),
        };

        let elapsed_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;

        PersistedState {
            version: PersistedState::VERSION,
            mode,
            passcode,
            failed_attempts,
            elapsed_ms,
        }
    }
    /// Restore *and* immediately prime the FSM with the current physical door state.
    ///
    /// Callers should apply the returned actions before emitting TimerTick.
    pub fn restore_primed(snapshot: PersistedState, door_now: DoorPhysicalState) -> Option<(Self, Actions<MAX_ACTIONS>)> {
        let state = Self::restore(snapshot)?;
        let (next, acts) = state.next(Event::DoorSensorChanged(door_now));
        Some((next, acts))
    }

    /// Restore from a persisted snapshot.
    pub fn restore(snapshot: PersistedState) -> Option<Self> {
        if !snapshot.validate() {
            return None;
        }

        let passcode = snapshot.passcode.to_buffer()?;
        let elapsed = Duration::from_millis(snapshot.elapsed_ms as u64);

        let state = match snapshot.mode {
            PersistedMode::Setup => SecurityState::Setup { buffer: passcode },
            PersistedMode::Locked => SecurityState::Locked {
                passcode,
                guess: PasscodeBuffer::default(),
                failed_attempts: snapshot.failed_attempts,
            },
            PersistedMode::Lockout => SecurityState::Lockout { passcode, elapsed },
            #[cfg(feature = "acoustic_unlock")]
            PersistedMode::PendingAudio => SecurityState::PendingAudio { passcode, elapsed },
            PersistedMode::Unlocked => SecurityState::Unlocked {
                passcode,
                elapsed,
                door: DoorPhysicalState::Closed, // best-effort default; will correct on next sensor event
            },
            PersistedMode::Alarm => SecurityState::Alarm { passcode, elapsed },
        };

        Some(state)
    }
}

fn add_duration_saturating(a: Duration, b: Duration) -> Duration {
    a.checked_add(b).unwrap_or(Duration::MAX)
}

impl SecurityState {
    /// Pure state transition.
    ///
    /// Returns the next state plus the `Action`s required to make hardware match the new state.
    #[must_use]
    pub fn next(self, event: Event) -> (Self, Actions<MAX_ACTIONS>) {
        use Event::*;
        use SecurityState::*;

        match (self, event) {
            // --- MODE 1: SETUP ---
            (Setup { mut buffer }, Keypress(d)) => {
                buffer.push(d);
                let len = buffer.len();
                (Setup { buffer }, actions![Action::UpdateDisplayLen(len)])
            }
            (Setup { mut buffer }, Clear) => {
                buffer.clear();
                (Setup { buffer }, actions![Action::UpdateDisplayLen(0)])
            }
            (Setup { buffer }, Enter) if buffer.len() >= MIN_PASSCODE_LEN => {
                (
                    Locked {
                        passcode: buffer,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    },
                    actions![Action::UpdateDisplayLen(0), Action::SetDoorLock(true)],
                )
            }
            (Setup { buffer }, Enter) => (Setup { buffer }, actions![]),
            (Setup { buffer }, TimerTick(_)) => (Setup { buffer }, actions![]),
            (Setup { buffer }, DoorSensorChanged(_)) => (Setup { buffer }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (Setup { buffer }, AudioFrequency(_)) => (Setup { buffer }, actions![]),

            // --- MODE 2: LOCKED ---
            (
                Locked {
                    passcode,
                    mut guess,
                    failed_attempts,
                },
                Keypress(d),
            ) => {
                guess.push(d);
                let len = guess.len();
                (
                    Locked {
                        passcode,
                        guess,
                        failed_attempts,
                    },
                    actions![Action::UpdateDisplayLen(len)],
                )
            }
            (
                Locked {
                    passcode,
                    mut guess,
                    failed_attempts,
                },
                Clear,
            ) => {
                guess.clear();
                (
                    Locked {
                        passcode,
                        guess,
                        failed_attempts,
                    },
                    actions![Action::UpdateDisplayLen(0)],
                )
            }
            (
                Locked {
                    passcode,
                    mut guess,
                    failed_attempts,
                },
                Enter,
            ) => {
                // Usability hardening: don't count empty submits as a failed attempt.
                if guess.is_empty() {
                    return (
                        Locked {
                            passcode,
                            guess,
                            failed_attempts,
                        },
                        actions![Action::UpdateDisplayLen(0)],
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
                            actions![Action::UpdateDisplayLen(0), Action::SetDoorLock(true)],
                        )
                    }

                    #[cfg(not(feature = "acoustic_unlock"))]
                    {
                        (
                            Unlocked {
                                passcode,
                                elapsed: Duration::ZERO,
                                door: DoorPhysicalState::Closed,
                            },
                            actions![Action::SetDoorLock(false), Action::UpdateDisplayLen(0)],
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
                            actions![
                                Action::UpdateDisplayLen(0),
                                Action::SoundAlarm(true),
                                Action::SetDoorLock(true)
                            ],
                        )
                    } else {
                        (
                            Locked {
                                passcode,
                                guess,
                                failed_attempts: new_attempts,
                            },
                            actions![Action::UpdateDisplayLen(0)],
                        )
                    }
                }
            }
            (
                Locked {
                    passcode,
                    mut guess,
                    failed_attempts: _,
                },
                DoorSensorChanged(DoorPhysicalState::Open),
            ) => {
                // Treat "door opened while we believe we're secured" as intrusion -> Alarm.
                guess.clear();
                (
                    Alarm {
                        passcode,
                        elapsed: Duration::ZERO,
                    },
                    actions![
                        Action::SoundAlarm(true),
                        Action::SetDoorLock(true),
                        Action::UpdateDisplayLen(0)
                    ],
                )
            }
            (Locked { passcode, guess, failed_attempts }, DoorSensorChanged(DoorPhysicalState::Closed)) => {
                (
                    Locked { passcode, guess, failed_attempts },
                    actions![]
                )
            }
            (Locked { passcode, guess, failed_attempts }, TimerTick(_)) => {
                (Locked { passcode, guess, failed_attempts }, actions![])
            }
            #[cfg(feature = "acoustic_unlock")]
            (Locked { passcode, guess, failed_attempts }, AudioFrequency(_)) => {
                (Locked { passcode, guess, failed_attempts }, actions![])
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
                        actions![
                            Action::SoundAlarm(false),
                            Action::SetDoorLock(true),
                            Action::UpdateDisplayLen(0)
                        ],
                    )
                } else {
                    (
                        Lockout {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        actions![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }
            (Lockout { passcode, elapsed }, DoorSensorChanged(DoorPhysicalState::Open)) => {
                // Stay in lockout but assert secure posture.
                (
                    Lockout { passcode, elapsed },
                    actions![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                )
            }
            (Lockout { passcode, elapsed }, DoorSensorChanged(DoorPhysicalState::Closed)) => {
                (Lockout { passcode, elapsed }, actions![])
            }
            (Lockout { passcode, elapsed }, Keypress(_)) => (Lockout { passcode, elapsed }, actions![]),
            (Lockout { passcode, elapsed }, Enter) => (Lockout { passcode, elapsed }, actions![]),
            (Lockout { passcode, elapsed }, Clear) => (Lockout { passcode, elapsed }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (Lockout { passcode, elapsed }, AudioFrequency(_)) => (Lockout { passcode, elapsed }, actions![]),

            // --- MODE 4: PENDING AUDIO (MFA Challenge) ---
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed: _ }, AudioFrequency(freq)) => {
                if verify_audio_challenge(&passcode, freq) {
                    (
                        Unlocked {
                            passcode,
                            elapsed: Duration::ZERO,
                            door: DoorPhysicalState::Closed,
                        },
                        actions![Action::SetDoorLock(false)],
                    )
                } else {
                    (
                        Alarm {
                            passcode,
                            elapsed: Duration::ZERO,
                        },
                        actions![Action::SoundAlarm(true), Action::SetDoorLock(true)],
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
                        actions![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                    )
                } else {
                    (
                        PendingAudio {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        actions![Action::SetDoorLock(true)],
                    )
                }
            }
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, DoorSensorChanged(_)) => {
                (PendingAudio { passcode, elapsed }, actions![Action::SetDoorLock(true)])
            }
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, Keypress(_)) => (PendingAudio { passcode, elapsed }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, Enter) => (PendingAudio { passcode, elapsed }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, Clear) => (PendingAudio { passcode, elapsed }, actions![]),

            // --- MODE 5: UNLOCKED ---
            (Unlocked { passcode, elapsed, door }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(elapsed, dt);

                if new_elapsed >= UNLOCKED_DURATION {
                    match door {
                        DoorPhysicalState::Closed => (
                            Locked {
                                passcode,
                                guess: PasscodeBuffer::default(),
                                failed_attempts: 0,
                            },
                            actions![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                        ),
                        DoorPhysicalState::Open => (
                            // Door is open: do NOT fire the bolt.
                            // Stay unlocked; latch will occur once we observe Closed.
                            Unlocked {
                                passcode,
                                elapsed: UNLOCKED_DURATION,
                                door,
                            },
                            actions![Action::SetDoorLock(false)],
                        ),
                    }
                } else {
                    (
                        Unlocked {
                            passcode,
                            elapsed: new_elapsed,
                            door,
                        },
                        actions![Action::SetDoorLock(false)],
                    )
                }
            }
            (Unlocked { passcode, elapsed, .. }, DoorSensorChanged(new_door)) => {
                // If we've already “expired” and the door just became closed, lock immediately.
                if elapsed >= UNLOCKED_DURATION && new_door == DoorPhysicalState::Closed {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        actions![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                    )
                } else {
                    (
                        Unlocked {
                            passcode,
                            elapsed,
                            door: new_door,
                        },
                        actions![],
                    )
                }
            }
            (Unlocked { passcode, elapsed, door }, Keypress(_)) => (Unlocked { passcode, elapsed, door }, actions![]),
            (Unlocked { passcode, elapsed, door }, Enter) => (Unlocked { passcode, elapsed, door }, actions![]),
            (Unlocked { passcode, elapsed, door }, Clear) => (Unlocked { passcode, elapsed, door }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (Unlocked { passcode, elapsed, door }, AudioFrequency(_)) => {
                (Unlocked { passcode, elapsed, door }, actions![])
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
                        actions![
                            Action::SoundAlarm(false),
                            Action::SetDoorLock(true),
                            Action::UpdateDisplayLen(0)
                        ],
                    )
                } else {
                    (
                        Alarm {
                            passcode,
                            elapsed: new_elapsed,
                        },
                        actions![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }
            (Alarm { passcode, elapsed }, DoorSensorChanged(_)) => {
                (Alarm { passcode, elapsed }, actions![Action::SoundAlarm(true), Action::SetDoorLock(true)])
            }
            (Alarm { passcode, elapsed }, Keypress(_)) => (Alarm { passcode, elapsed }, actions![]),
            (Alarm { passcode, elapsed }, Enter) => (Alarm { passcode, elapsed }, actions![]),
            (Alarm { passcode, elapsed }, Clear) => (Alarm { passcode, elapsed }, actions![]),
            #[cfg(feature = "acoustic_unlock")]
            (Alarm { passcode, elapsed }, AudioFrequency(_)) => (Alarm { passcode, elapsed }, actions![]),
        }
    }
}

// NOTE: Never return true without authenticated cryptographic proof.
// This must NOT be a simple "freq near passcode" logic in production.
#[cfg(feature = "acoustic_unlock")]
fn verify_audio_challenge(_p: &PasscodeBuffer, _freq: u32) -> bool {
    false // Default to secure failure for this stub.
}