//! # Keypad Lock FSM (pure core, diffed outputs, sealed persistence)
//!
//! A memory-safe, side-effect-free finite state machine (FSM) modeling a secure keypad lock.
//!
//! Core transition is pure:
//!
//! ```text
//! Event + CurrentState -> (NextState, Actions)
//! ```
//!
//! All hardware side-effects are represented as `Action` values and must be performed externally.
//!
//! ## Notable design choices
//! - **No action spam:** the FSM tracks desired outputs and emits only *changes* (diff-based).
//! - **Secret hygiene:** passcode buffers are `ZeroizeOnDrop` and never revealed via `Debug`.
//! - **Persistence:** supports sealing/unsealing passcode via an injected pure `PasscodeSealer`
//!   (so you don't store plaintext in NVRAM by default).

#![forbid(unsafe_code)]

use core::time::Duration;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum passcode length accepted during setup.
pub const MIN_PASSCODE_LEN: usize = 3;
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

// -----------------------------
// Policy toggles (explicit)
// -----------------------------

/// If `true`, opening the door while in `Locked` mode triggers `Alarm`.
///
/// This is a tamper-response policy: on many systems the door should not be able to open while locked
/// unless the lock is bypassed or the sensor is spoofed.
///
/// If `false`, the FSM treats `DoorSensorChanged(Open)` while locked as a sensor anomaly and keeps
/// the system locked with alarm off.
pub const ALARM_ON_DOOR_OPEN_WHEN_LOCKED: bool = true;

/// MFA timeout when `acoustic_unlock` is enabled.
#[cfg(feature = "acoustic_unlock")]
pub const MFA_TIMEOUT: Duration = Duration::from_secs(5);

/// Max number of actions emitted by any single transition.
pub const MAX_ACTIONS: usize = 6;

// -----------------------------
// Actions (fixed-cap, no alloc)
// -----------------------------

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
    #[must_use]
    pub fn push(&mut self, a: Action) -> bool {
        if self.len < N {
            self.buf[self.len] = Some(a);
            self.len += 1;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn push_debug(&mut self, a: Action) -> bool {
        let ok = self.push(a);
        debug_assert!(ok, "Actions overflow: increase MAX_ACTIONS or reduce emitted actions");
        ok
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
        core::iter::Take<core::array::IntoIter<Option<Action>, N>>,
        fn(Option<Action>) -> Option<Action>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn keep(x: Option<Action>) -> Option<Action> {
            x
        }
        let len = self.len;
        self.buf
            .into_iter()
            .take(len)
            .filter_map(keep as fn(_) -> _)
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
            let _ = out.push_debug($a);
        )+
        out
    }};
}

// -----------------------------
// Domain types
// -----------------------------

/// A single keypad digit (0-9).
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

    /// User feedback (optional but recommended UX hardening).
    /// Your executor can map this to a beep, LED flash, etc.
    Feedback(Feedback),
}

/// High-level feedback hints (no secrets).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Feedback {
    /// Keypress ignored because buffer is full.
    BufferFull,
    /// Enter ignored due to too-short passcode during setup.
    PasscodeTooShort,
    /// Bad PIN entered.
    IncorrectPin,
    /// Correct PIN entered.
    PinAccepted,
    /// Lockout started.
    LockoutStarted,
}

/// A bounded buffer holding a passcode / guess (ZeroizeOnDrop).
///
/// Comparisons are performed in a fixed-iteration, constant-time style via `subtle`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasscodeBuffer {
    digits: [u8; MAX_PASSCODE_LEN],
    len: u8, // 0..=MAX_PASSCODE_LEN
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
        f.debug_struct("PasscodeBuffer")
            .field("len", &self.len)
            .field("digits", &"[REDACTED]")
            .finish()
    }
}

impl PasscodeBuffer {
    /// Push a digit, returning whether it was accepted.
    #[must_use]
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

    /// Zeroize all digits and reset length.
    pub fn clear(&mut self) {
        self.digits.zeroize();
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Constant-time style equality of digits + length using `subtle`.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let digits_eq = self.digits.ct_eq(&other.digits);
        let len_eq = self.len.ct_eq(&other.len);
        digits_eq & len_eq
    }

    /// Constant-time style match requiring non-empty input.
    pub fn matches(&self, other: &Self) -> bool {
        let eq = self.ct_eq(other);
        let non_empty = self.len.ct_ne(&0u8);
        bool::from(eq & non_empty)
    }

    /// For sealing/persistence only: copy out the fixed buffer + len.
    fn raw_parts(&self) -> ([u8; MAX_PASSCODE_LEN], u8) {
        (self.digits, self.len)
    }

    /// Restore from raw parts after validation.
    fn from_raw_parts(digits: [u8; MAX_PASSCODE_LEN], len: u8) -> Option<Self> {
        if (len as usize) > MAX_PASSCODE_LEN {
            return None;
        }

        let used_len = len as usize;

        // Validate only the used portion (tail is normalized).
        if digits[..used_len].iter().any(|d| *d > 9) {
            return None;
        }

        // Normalize tail to zero to avoid coupling correctness/tamper semantics to the sealer's behavior.
        let mut normalized = digits;
        for d in normalized[used_len..].iter_mut() {
            *d = 0;
        }

        Some(Self {
            digits: normalized,
            len,
        })
    }
}

// -----------------------------
// Persistence with sealing
// -----------------------------

/// Seals/unseals passcode bytes for persistence.
///
/// `BLOB_LEN` is a const generic so this compiles on stable Rust.
pub trait PasscodeSealer<const BLOB_LEN: usize> {
    /// Seals the passcode raw parts into an opaque blob.
    fn seal(&self, digits: [u8; MAX_PASSCODE_LEN], len: u8) -> [u8; BLOB_LEN];

    /// Unseals a blob into raw parts. Return `None` if invalid/tampered.
    fn unseal(&self, blob: [u8; BLOB_LEN]) -> Option<([u8; MAX_PASSCODE_LEN], u8)>;
}

/// Compact persisted state (opaque passcode blob).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PersistedState<const BLOB_LEN: usize> {
    pub version: u8,
    pub mode: PersistedMode,
    pub passcode_blob: [u8; BLOB_LEN],
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

impl<const BLOB_LEN: usize> PersistedState<BLOB_LEN> {
    pub const VERSION: u8 = 2;

    /// Strict validation of invariant combinations. This prevents impossible states from being restored.
    pub fn validate_strict(&self) -> bool {
        if self.version != Self::VERSION {
            return false;
        }
        if self.failed_attempts > LOCKOUT_THRESHOLD {
            return false;
        }

        match self.mode {
            PersistedMode::Setup => self.failed_attempts == 0 && self.elapsed_ms == 0,
            PersistedMode::Locked => {
                // In locked mode, attempts may be 0..(threshold-1). Threshold implies lockout.
                self.failed_attempts < LOCKOUT_THRESHOLD && self.elapsed_ms == 0
            }
            PersistedMode::Lockout => {
                // Lockout implies the threshold was reached.
                self.failed_attempts == LOCKOUT_THRESHOLD
            }
            #[cfg(feature = "acoustic_unlock")]
            PersistedMode::PendingAudio => self.failed_attempts == 0,
            PersistedMode::Unlocked => self.failed_attempts == 0,
            PersistedMode::Alarm => self.failed_attempts == 0,
        }
    }
}

// -----------------------------
// FSM internals (mode + outputs)
// -----------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Outputs {
    display_len: u8,
    alarm_on: bool,
    door_locked: bool,
}

impl Outputs {
    const fn new() -> Self {
        Self {
            display_len: 0,
            alarm_on: false,
            door_locked: true, // safe default posture
        }
    }
}

/// Secret-bearing internal mode.
#[derive(Debug)]
enum Mode {
    Setup { buffer: PasscodeBuffer },

    Locked {
        passcode: PasscodeBuffer,
        guess: PasscodeBuffer,
        failed_attempts: u8,
    },

    Lockout { passcode: PasscodeBuffer, elapsed: Duration },

    #[cfg(feature = "acoustic_unlock")]
    PendingAudio { passcode: PasscodeBuffer, elapsed: Duration },

    Unlocked {
        passcode: PasscodeBuffer,
        elapsed: Duration,
        door: DoorPhysicalState,
    },

    Alarm { passcode: PasscodeBuffer, elapsed: Duration },
}

/// Public FSM: mode + last desired outputs.
#[derive(Debug)]
pub struct SecurityState {
    mode: Mode,
    out: Outputs,
}

impl Default for SecurityState {
    fn default() -> Self {
        Self {
            mode: Mode::Setup {
                buffer: PasscodeBuffer::default(),
            },
            out: Outputs::new(),
        }
    }
}

fn add_duration_saturating(a: Duration, b: Duration) -> Duration {
    a.checked_add(b).unwrap_or(Duration::MAX)
}

impl SecurityState {
    fn emit_output_diff(
        mut acts: Actions<MAX_ACTIONS>,
        prev: Outputs,
        next: Outputs,
    ) -> Actions<MAX_ACTIONS> {
        if prev.display_len != next.display_len {
            let _ = acts.push_debug(Action::UpdateDisplayLen(next.display_len));
        }
        if prev.alarm_on != next.alarm_on {
            let _ = acts.push_debug(Action::SoundAlarm(next.alarm_on));
        }
        if prev.door_locked != next.door_locked {
            let _ = acts.push_debug(Action::SetDoorLock(next.door_locked));
        }
        acts
    }

    /// Create a persistence snapshot suitable for writing to EEPROM/NVRAM.
    ///
    /// Uses the provided `sealer` to avoid plaintext storage.
    #[must_use]
    pub fn snapshot_with<const B: usize, S: PasscodeSealer<B>>(
        &self,
        sealer: &S,
    ) -> PersistedState<B> {
        let (mode_tag, passcode_buf, failed_attempts, elapsed) = match &self.mode {
            Mode::Setup { buffer } => (PersistedMode::Setup, buffer, 0, Duration::ZERO),
            Mode::Locked {
                passcode,
                guess: _,
                failed_attempts,
            } => (PersistedMode::Locked, passcode, *failed_attempts, Duration::ZERO),
            Mode::Lockout { passcode, elapsed } => (
                PersistedMode::Lockout,
                passcode,
                LOCKOUT_THRESHOLD,
                *elapsed,
            ),
            #[cfg(feature = "acoustic_unlock")]
            Mode::PendingAudio { passcode, elapsed } => {
                (PersistedMode::PendingAudio, passcode, 0, *elapsed)
            }
            Mode::Unlocked { passcode, elapsed, .. } => (PersistedMode::Unlocked, passcode, 0, *elapsed),
            Mode::Alarm { passcode, elapsed } => (PersistedMode::Alarm, passcode, 0, *elapsed),
        };

        let (digits, len) = passcode_buf.raw_parts();
        let passcode_blob = sealer.seal(digits, len);

        let elapsed_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;

        PersistedState {
            version: PersistedState::<B>::VERSION,
            mode: mode_tag,
            passcode_blob,
            failed_attempts,
            elapsed_ms,
        }
    }

    /// Restore *and* immediately prime the FSM with the current physical door state.
    ///
    /// Callers should apply the returned actions before emitting TimerTick.
    pub fn restore_primed_with<const B: usize, S: PasscodeSealer<B>>(
        sealer: &S,
        snapshot: PersistedState<B>,
        door_now: DoorPhysicalState,
    ) -> Option<(Self, Actions<MAX_ACTIONS>)> {
        let state = Self::restore_with(sealer, snapshot)?;
        let (next, acts) = state.next(Event::DoorSensorChanged(door_now));
        Some((next, acts))
    }

    /// Restore from a persisted snapshot using a sealer.
    pub fn restore_with<const B: usize, S: PasscodeSealer<B>>(
        sealer: &S,
        snapshot: PersistedState<B>,
    ) -> Option<Self> {
        if !snapshot.validate_strict() {
            return None;
        }

        let (digits, len) = sealer.unseal(snapshot.passcode_blob)?;
        let passcode = PasscodeBuffer::from_raw_parts(digits, len)?;
        let elapsed = Duration::from_millis(snapshot.elapsed_ms as u64);

        let mode = match snapshot.mode {
            PersistedMode::Setup => Mode::Setup { buffer: passcode },
            PersistedMode::Locked => Mode::Locked {
                passcode,
                guess: PasscodeBuffer::default(),
                failed_attempts: snapshot.failed_attempts,
            },
            PersistedMode::Lockout => Mode::Lockout { passcode, elapsed },
            #[cfg(feature = "acoustic_unlock")]
            PersistedMode::PendingAudio => Mode::PendingAudio { passcode, elapsed },
            PersistedMode::Unlocked => Mode::Unlocked {
                passcode,
                elapsed,
                door: DoorPhysicalState::Closed, // best-effort; will correct on next sensor event
            },
            PersistedMode::Alarm => Mode::Alarm { passcode, elapsed },
        };

        // Restore to safe posture (locked, alarm off, display cleared).
        Some(Self { mode, out: Outputs::new() })
    }

    /// Pure state transition. Emits *only* output changes + explicit feedback actions.
    #[must_use]
    pub fn next(mut self, event: Event) -> (Self, Actions<MAX_ACTIONS>) {
        use Event::*;

        let prev_out = self.out;
        let mut next_out = prev_out;
        let mut acts = actions![];

        // Setters for desired outputs (diff emitted at end).
        let mut set_display = |len: u8| next_out.display_len = len;
        let mut set_alarm = |on: bool| next_out.alarm_on = on;
        let mut set_lock = |locked: bool| next_out.door_locked = locked;

        match (&mut self.mode, event) {
            // -----------------
            // MODE 1: SETUP
            // -----------------
            (Mode::Setup { buffer }, Keypress(d)) => {
                if buffer.push(d) {
                    set_display(buffer.len() as u8);
                } else {
                    let _ = acts.push_debug(Action::Feedback(Feedback::BufferFull));
                    set_display(buffer.len() as u8);
                }
                set_lock(true);
                set_alarm(false);
            }
            (Mode::Setup { buffer }, Clear) => {
                buffer.clear();
                set_display(0);
                set_lock(true);
                set_alarm(false);
            }
            (Mode::Setup { buffer }, Enter) => {
                if buffer.len() >= MIN_PASSCODE_LEN {
                    let passcode = core::mem::take(buffer);
                    self.mode = Mode::Locked {
                        passcode,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    };
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    let _ = acts.push_debug(Action::Feedback(Feedback::PasscodeTooShort));
                    set_display(buffer.len() as u8);
                    set_lock(true);
                    set_alarm(false);
                }
            }
            (Mode::Setup { .. }, TimerTick(_)) => {
                set_lock(true);
                set_alarm(false);
            }
            (Mode::Setup { .. }, DoorSensorChanged(_)) => {
                set_lock(true);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::Setup { .. }, AudioFrequency(_)) => {
                set_lock(true);
                set_alarm(false);
            }

            // -----------------
            // MODE 2: LOCKED
            // -----------------
            (Mode::Locked { guess, .. }, Keypress(d)) => {
                if guess.push(d) {
                    set_display(guess.len() as u8);
                } else {
                    let _ = acts.push_debug(Action::Feedback(Feedback::BufferFull));
                    set_display(guess.len() as u8);
                }
                set_lock(true);
                set_alarm(false);
            }
            (Mode::Locked { guess, .. }, Clear) => {
                guess.clear();
                set_display(0);
                set_lock(true);
                set_alarm(false);
            }
            (
                Mode::Locked {
                    passcode,
                    guess,
                    failed_attempts,
                },
                Enter,
            ) => {
                if guess.is_empty() {
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    let ok = guess.matches(passcode);
                    guess.clear();
                    set_display(0);

                    if ok {
                        let _ = acts.push_debug(Action::Feedback(Feedback::PinAccepted));
                        #[cfg(feature = "acoustic_unlock")]
                        {
                            let passcode = core::mem::take(passcode);
                            self.mode = Mode::PendingAudio {
                                passcode,
                                elapsed: Duration::ZERO,
                            };
                            set_lock(true);
                            set_alarm(false);
                        }
                        #[cfg(not(feature = "acoustic_unlock"))]
                        {
                            let passcode = core::mem::take(passcode);
                            self.mode = Mode::Unlocked {
                                passcode,
                                elapsed: Duration::ZERO,
                                door: DoorPhysicalState::Closed,
                            };
                            set_lock(false);
                            set_alarm(false);
                        }
                    } else {
                        let _ = acts.push_debug(Action::Feedback(Feedback::IncorrectPin));
                        let new_attempts = failed_attempts.saturating_add(1);

                        if new_attempts >= LOCKOUT_THRESHOLD {
                            let _ = acts.push_debug(Action::Feedback(Feedback::LockoutStarted));
                            let passcode = core::mem::take(passcode);
                            self.mode = Mode::Lockout {
                                passcode,
                                elapsed: Duration::ZERO,
                            };
                            set_lock(true);
                            set_alarm(true);
                        } else {
                            *failed_attempts = new_attempts;
                            set_lock(true);
                            set_alarm(false);
                        }
                    }
                }
            }
            (Mode::Locked { passcode, guess, .. }, DoorSensorChanged(DoorPhysicalState::Open)) => {
                // Explicit tamper-response policy: door opened while locked triggers alarm if enabled.
                // If disabled, treat as a sensor anomaly and remain locked (alarm off).
                guess.clear();
                set_display(0);
                set_lock(true);
                if ALARM_ON_DOOR_OPEN_WHEN_LOCKED {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Alarm {
                        passcode,
                        elapsed: Duration::ZERO,
                    };
                    set_alarm(true);
                } else {
                    set_alarm(false);
                }
            }
            (Mode::Locked { .. }, DoorSensorChanged(DoorPhysicalState::Closed)) => {
                set_lock(true);
                set_alarm(false);
            }
            (Mode::Locked { .. }, TimerTick(_)) => {
                set_lock(true);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::Locked { .. }, AudioFrequency(_)) => {
                set_lock(true);
                set_alarm(false);
            }

            // -----------------
            // MODE 3: LOCKOUT
            // -----------------
            (Mode::Lockout { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(*elapsed, dt);
                *elapsed = new_elapsed;

                if new_elapsed >= LOCKOUT_DURATION {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Locked {
                        passcode,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    };
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    set_lock(true);
                    set_alarm(true);
                }
            }
            (Mode::Lockout { .. }, DoorSensorChanged(_)) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Lockout { .. }, Keypress(_)) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Lockout { .. }, Enter) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Lockout { .. }, Clear) => {
                set_lock(true);
                set_alarm(true);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::Lockout { .. }, AudioFrequency(_)) => {
                set_lock(true);
                set_alarm(true);
            }

            // -----------------
            // MODE 4: PENDING AUDIO (MFA)
            // -----------------
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { passcode, .. }, AudioFrequency(freq)) => {
                if verify_audio_challenge(passcode, freq) {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Unlocked {
                        passcode,
                        elapsed: Duration::ZERO,
                        door: DoorPhysicalState::Closed,
                    };
                    set_lock(false);
                    set_alarm(false);
                } else {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Alarm {
                        passcode,
                        elapsed: Duration::ZERO,
                    };
                    set_lock(true);
                    set_alarm(true);
                }
                set_display(0);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(*elapsed, dt);
                *elapsed = new_elapsed;

                if new_elapsed >= MFA_TIMEOUT {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Locked {
                        passcode,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    };
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    set_lock(true);
                    set_alarm(false);
                }
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { .. }, DoorSensorChanged(_)) => {
                set_lock(true);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { .. }, Keypress(_)) => {
                set_lock(true);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { .. }, Enter) => {
                set_lock(true);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::PendingAudio { .. }, Clear) => {
                set_lock(true);
                set_alarm(false);
            }

            // -----------------
            // MODE 5: UNLOCKED
            // -----------------
            (Mode::Unlocked { passcode, elapsed, door }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(*elapsed, dt);
                *elapsed = new_elapsed;

                if new_elapsed >= UNLOCKED_DURATION {
                    match *door {
                        DoorPhysicalState::Closed => {
                            let passcode = core::mem::take(passcode);
                            self.mode = Mode::Locked {
                                passcode,
                                guess: PasscodeBuffer::default(),
                                failed_attempts: 0,
                            };
                            set_display(0);
                            set_lock(true);
                            set_alarm(false);
                        }
                        DoorPhysicalState::Open => {
                            *elapsed = UNLOCKED_DURATION;
                            set_lock(false);
                            set_alarm(false);
                        }
                    }
                } else {
                    set_lock(false);
                    set_alarm(false);
                }
            }
            (Mode::Unlocked { passcode, elapsed, door }, DoorSensorChanged(new_door)) => {
                *door = new_door;

                if *elapsed >= UNLOCKED_DURATION && new_door == DoorPhysicalState::Closed {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Locked {
                        passcode,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    };
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    set_lock(false);
                    set_alarm(false);
                }
            }
            (Mode::Unlocked { .. }, Keypress(_)) => {
                set_lock(false);
                set_alarm(false);
            }
            (Mode::Unlocked { .. }, Enter) => {
                set_lock(false);
                set_alarm(false);
            }
            (Mode::Unlocked { .. }, Clear) => {
                set_lock(false);
                set_alarm(false);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::Unlocked { .. }, AudioFrequency(_)) => {
                set_lock(false);
                set_alarm(false);
            }

            // -----------------
            // MODE 6: ALARM
            // -----------------
            (Mode::Alarm { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = add_duration_saturating(*elapsed, dt);
                *elapsed = new_elapsed;

                if new_elapsed >= ALARM_DURATION {
                    let passcode = core::mem::take(passcode);
                    self.mode = Mode::Locked {
                        passcode,
                        guess: PasscodeBuffer::default(),
                        failed_attempts: 0,
                    };
                    set_display(0);
                    set_lock(true);
                    set_alarm(false);
                } else {
                    set_lock(true);
                    set_alarm(true);
                }
            }
            (Mode::Alarm { .. }, DoorSensorChanged(_)) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Alarm { .. }, Keypress(_)) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Alarm { .. }, Enter) => {
                set_lock(true);
                set_alarm(true);
            }
            (Mode::Alarm { .. }, Clear) => {
                set_lock(true);
                set_alarm(true);
            }
            #[cfg(feature = "acoustic_unlock")]
            (Mode::Alarm { .. }, AudioFrequency(_)) => {
                set_lock(true);
                set_alarm(true);
            }
        }

        acts = Self::emit_output_diff(acts, prev_out, next_out);
        self.out = next_out;

        (self, acts)
    }
}

// -----------------------------
// MFA stub
// -----------------------------

// NOTE: Never return true without authenticated cryptographic proof.
// This must NOT be a simple "freq near passcode" logic in production.
#[cfg(feature = "acoustic_unlock")]
fn verify_audio_challenge(_p: &PasscodeBuffer, _freq: u32) -> bool {
    false
}