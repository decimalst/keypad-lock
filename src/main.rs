use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

// 1. Memory Safety & Type Safety
// Digit doesn't need Zeroize; it's Copy and ephemeral. Keep the secret handling in the buffers.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Digit(u8);

impl Digit {
    pub fn new(val: u8) -> Option<Self> {
        if val <= 9 { Some(Self(val)) } else { None }
    }
    pub fn value(self) -> u8 { self.0 }
}

// 2. Strict Encapsulation + Memory Hygiene
#[derive(Clone, Debug, Default, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct PasscodeBuffer {
    digits: [u8; 6],
    len: u8, // strictly private
}

impl PasscodeBuffer {
    pub fn push(&mut self, d: Digit) {
        if self.len < 6 {
            self.digits[self.len as usize] = d.value();
            self.len += 1;
        }
    }

    pub fn clear(&mut self) {
        self.digits.zeroize();
        self.len = 0;
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    // Branchless digit + length compare.
    // Note: For "hard" constant-time guarantees across platforms/optimizers,
    // prefer a vetted crate like `subtle`, but this is a solid baseline.
    pub fn matches(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;

        for i in 0..6 {
            diff |= self.digits[i] ^ other.digits[i];
        }

        diff |= self.len ^ other.len;

        // Require non-empty (kept as a final check)
        let non_empty = (self.len != 0) as u8;

        (diff == 0) && (non_empty == 1)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Keypress(Digit),
    Enter,
    Clear,
    AudioFrequency(u32),
    TimerTick(Duration),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    UpdateDisplayLen(u8),
    SoundAlarm(bool),
    SetDoorLock(bool), // true = locked, false = unlocked
}

#[derive(Clone, Debug, PartialEq)]
pub enum SecurityState {
    Setup { buffer: PasscodeBuffer },
    Locked { passcode: PasscodeBuffer, guess: PasscodeBuffer, failed_attempts: u8 },
    Lockout { passcode: PasscodeBuffer, elapsed: Duration },      // Penalty box
    PendingAudio { passcode: PasscodeBuffer, elapsed: Duration }, // MFA step
    Unlocked { passcode: PasscodeBuffer, elapsed: Duration },
    Alarm { passcode: PasscodeBuffer, elapsed: Duration },
}

impl SecurityState {
    pub fn next(self, event: Event) -> (Self, Vec<Action>) {
        use Event::*;
        use SecurityState::*;

        match (self, event) {
            // --- MODE 1: SETUP ---
            (Setup { mut buffer }, Keypress(d)) => {
                buffer.push(d);
                let len = buffer.len(); // capture before move
                (Setup { buffer }, vec![Action::UpdateDisplayLen(len)])
            }
            (Setup { mut buffer }, Clear) => {
                buffer.clear();
                (Setup { buffer }, vec![Action::UpdateDisplayLen(0)])
            }
            (Setup { buffer }, Enter) if buffer.len() >= 3 => {
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
            (Locked { passcode, mut guess, failed_attempts }, Keypress(d)) => {
                guess.push(d);
                let len = guess.len(); // capture before move
                (
                    Locked { passcode, guess, failed_attempts },
                    vec![Action::UpdateDisplayLen(len)],
                )
            }
            (Locked { passcode, mut guess, failed_attempts }, Clear) => {
                guess.clear();
                (
                    Locked { passcode, guess, failed_attempts },
                    vec![Action::UpdateDisplayLen(0)],
                )
            }
            (Locked { passcode, mut guess, failed_attempts }, Enter) => {
                if guess.matches(&passcode) {
                    guess.clear(); // Clean up memory

                    #[cfg(feature = "acoustic_unlock")]
                    {
                        (
                            PendingAudio { passcode, elapsed: Duration::ZERO },
                            vec![Action::UpdateDisplayLen(0)],
                        )
                    }

                    #[cfg(not(feature = "acoustic_unlock"))]
                    {
                        (
                            Unlocked { passcode, elapsed: Duration::ZERO },
                            vec![Action::SetDoorLock(false), Action::UpdateDisplayLen(0)],
                        )
                    }
                } else {
                    guess.clear();

                    // Hardening: avoid overflow in adversarial/fuzz scenarios.
                    let new_attempts = failed_attempts.saturating_add(1);

                    if new_attempts >= 3 {
                        (
                            Lockout { passcode, elapsed: Duration::ZERO },
                            vec![Action::UpdateDisplayLen(0), Action::SoundAlarm(true)],
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
                let new_elapsed = elapsed + dt;
                if new_elapsed >= Duration::from_secs(30) {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SoundAlarm(false)],
                    )
                } else {
                    (Lockout { passcode, elapsed: new_elapsed }, vec![])
                }
            }

            // --- MODE 4: PENDING AUDIO (MFA Challenge) ---
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed: _ }, AudioFrequency(freq)) => {
                if verify_audio_challenge(&passcode, freq) {
                    (
                        Unlocked { passcode, elapsed: Duration::ZERO },
                        vec![Action::SetDoorLock(false)],
                    )
                } else {
                    (
                        Alarm { passcode, elapsed: Duration::ZERO },
                        vec![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }
            #[cfg(feature = "acoustic_unlock")]
            (PendingAudio { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = elapsed + dt;
                if new_elapsed >= Duration::from_secs(5) {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SetDoorLock(true)],
                    )
                } else {
                    (PendingAudio { passcode, elapsed: new_elapsed }, vec![])
                }
            }

            // --- MODE 5: UNLOCKED ---
            (Unlocked { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = elapsed + dt;
                if new_elapsed >= Duration::from_secs(10) {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SetDoorLock(true), Action::UpdateDisplayLen(0)],
                    )
                } else {
                    // Idempotent output assertion
                    (
                        Unlocked { passcode, elapsed: new_elapsed },
                        vec![Action::SetDoorLock(false)],
                    )
                }
            }

            // --- MODE 6: ALARM ---
            (Alarm { passcode, elapsed }, TimerTick(dt)) => {
                let new_elapsed = elapsed + dt;
                if new_elapsed >= Duration::from_secs(5) {
                    (
                        Locked {
                            passcode,
                            guess: PasscodeBuffer::default(),
                            failed_attempts: 0,
                        },
                        vec![Action::SoundAlarm(false), Action::SetDoorLock(true)],
                    )
                } else {
                    // Idempotent assertions during active alarm
                    (
                        Alarm { passcode, elapsed: new_elapsed },
                        vec![Action::SoundAlarm(true), Action::SetDoorLock(true)],
                    )
                }
            }

            // Catch-all: Drop invalid inputs (like typing during Lockout)
            (state, _) => (state, vec![]),
        }
    }
}

// NOTE: Never return true without authenticated cryptographic proof.
// This must NOT be a simple "freq near passcode" logic in production.
#[cfg(feature = "acoustic_unlock")]
fn verify_audio_challenge(_p: &PasscodeBuffer, _freq: u32) -> bool {
    false // Defaulting to secure fail for the stub
}

fn main() {
    println!("Security FSM compiled successfully.");
}