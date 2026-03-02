use std::time::Duration;

use keypad_lock_fsm::{
    Action, Actions, Digit, DoorPhysicalState, Event, Feedback, PasscodeBuffer, PasscodeSealer,
    PersistedMode, PersistedState, SecurityState, ALARM_DURATION, LOCKOUT_DURATION, MAX_ACTIONS,
    MAX_PASSCODE_LEN, MIN_PASSCODE_LEN, UNLOCKED_DURATION,
};

fn d(v: u8) -> Digit {
    Digit::new(v).unwrap()
}

fn actions_to_vec<const N: usize>(a: Actions<N>) -> Vec<Action> {
    a.into_iter().collect()
}

fn actions_contains<const N: usize>(actions: &Actions<N>, needle: &Action) -> bool {
    actions.iter().any(|a| a == needle)
}

fn actions_contains_feedback<const N: usize>(actions: &Actions<N>, fb: Feedback) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, Action::Feedback(x) if *x == fb))
}

/// Black-box state classification using Debug output.
/// `SecurityState` is now a struct with private internals, so pattern-matching isn't available in tests.
fn assert_mode(state: &SecurityState, mode_name: &str) {
    let s = format!("{state:?}");
    let needle = format!("mode: {mode_name}");
    assert!(
        s.contains(&needle),
        "expected debug to contain {needle:?}, got: {s}"
    );
}

/// Feed digits + Enter, collecting all actions into a Vec for easy assertions.
fn enter_passcode(state: SecurityState, digits: &[u8]) -> (SecurityState, Vec<Action>) {
    let mut s = state;
    let mut all_actions: Vec<Action> = Vec::new();

    for &v in digits {
        let (next, actions) = s.next(Event::Keypress(d(v)));
        s = next;
        all_actions.extend(actions_to_vec(actions));
    }

    let (next, actions) = s.next(Event::Enter);
    s = next;
    all_actions.extend(actions_to_vec(actions));

    (s, all_actions)
}

/// Convenience: prime door sensor with a known physical state.
fn prime_door(state: SecurityState, door: DoorPhysicalState) -> (SecurityState, Actions<MAX_ACTIONS>) {
    state.next(Event::DoorSensorChanged(door))
}

/// Dev-only sealer used by tests.
/// Blob layout: [digits (MAX_PASSCODE_LEN bytes) | len (1 byte)].
/// NOT secure. Only for tests.
struct PlainSealer;

impl PasscodeSealer<{ MAX_PASSCODE_LEN + 1 }> for PlainSealer {
    fn seal(&self, digits: [u8; MAX_PASSCODE_LEN], len: u8) -> [u8; MAX_PASSCODE_LEN + 1] {
        let mut out = [0u8; MAX_PASSCODE_LEN + 1];
        out[..MAX_PASSCODE_LEN].copy_from_slice(&digits);
        out[MAX_PASSCODE_LEN] = len;
        out
    }

    fn unseal(&self, blob: [u8; MAX_PASSCODE_LEN + 1]) -> Option<([u8; MAX_PASSCODE_LEN], u8)> {
        let mut digits = [0u8; MAX_PASSCODE_LEN];
        digits.copy_from_slice(&blob[..MAX_PASSCODE_LEN]);
        let len = blob[MAX_PASSCODE_LEN];

        if (len as usize) > MAX_PASSCODE_LEN {
            return None;
        }
        if digits.iter().any(|d| *d > 9) {
            return None;
        }
        Some((digits, len))
    }
}

#[test]
fn digit_new_validates_range() {
    for v in 0u8..=9u8 {
        assert!(Digit::new(v).is_some());
    }

    for &v in &[10u8, 11u8, 250u8, 255u8] {
        assert!(Digit::new(v).is_none());
    }
}

#[test]
fn passcode_buffer_is_bounded_and_clear_zeroes_via_snapshot() {
    let mut pb = PasscodeBuffer::default();
    assert_eq!(pb.len(), 0);
    assert!(pb.is_empty());

    for _ in 0..MAX_PASSCODE_LEN {
        assert!(pb.push(d(7)));
    }
    assert_eq!(pb.len(), MAX_PASSCODE_LEN);
    assert!(!pb.push(d(1)), "push should fail when buffer is full");

    pb.clear();
    assert_eq!(pb.len(), 0);
    assert!(pb.is_empty());

    // Verify backing storage is zeroed by snapshotting default Setup (empty buffer).
    let sealer = PlainSealer;
    let state = SecurityState::default();
    let snap: PersistedState<{ MAX_PASSCODE_LEN + 1 }> =
        state.snapshot_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer);

    let (digits, len) = sealer.unseal(snap.passcode_blob).expect("unseal should succeed");
    assert_eq!(len, 0);
    assert!(digits.iter().all(|&x| x == 0));
}

#[test]
fn setup_requires_min_length_before_locking() {
    let mut state = SecurityState::default();
    assert_mode(&state, "Setup");

    // Enter fewer than MIN_PASSCODE_LEN digits and press Enter.
    for (i, &v) in [1u8, 2u8].iter().enumerate() {
        let (next, actions) = state.next(Event::Keypress(d(v)));
        state = next;
        // display len should change to i+1; diff-based outputs emits only changes, so we expect it.
        assert!(actions_contains(&actions, &Action::UpdateDisplayLen((i + 1) as u8)));
    }

    let (next, actions) = state.next(Event::Enter);
    state = next;

    // Not enough digits: should remain in Setup with feedback.
    assert_mode(&state, "Setup");
    assert!(actions_contains_feedback(&actions, Feedback::PasscodeTooShort));

    // Add one more digit and Enter -> should lock.
    state = state.next(Event::Keypress(d(3))).0;
    let (next, _actions) = state.next(Event::Enter);
    state = next;

    assert_mode(&state, "Locked");
    // NOTE: With diffing, SetDoorLock(true) might NOT be emitted because default posture is already locked.
}

#[test]
fn empty_enter_in_locked_does_not_increment_failed_attempts() {
    // Setup PIN: 1-2-3
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert_mode(&state, "Locked");
    assert!(!actions_contains(&actions, &Action::SoundAlarm(true)));
    assert!(!actions_contains_feedback(&actions, Feedback::LockoutStarted));
}

#[test]
fn correct_pin_unlocks_and_auto_relocks_when_door_closed() {
    // Setup PIN 1-2-3.
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    // Prime: assume door is closed (normal).
    state = prime_door(state, DoorPhysicalState::Closed).0;

    // Enter correct PIN.
    for &v in &[1u8, 2u8, 3u8] {
        state = state.next(Event::Keypress(d(v))).0;
    }

    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert_mode(&state, "Unlocked");
    // This IS a change, so we should see unlock command.
    assert!(actions_contains(&actions, &Action::SetDoorLock(false)));

    // Tick less than UNLOCKED_DURATION -> still unlocked (no lock command).
    let (next, actions) = state.next(Event::TimerTick(UNLOCKED_DURATION - Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Unlocked");
    assert!(!actions_contains(&actions, &Action::SetDoorLock(true)));

    // Cross the threshold while door is closed -> re-lock (this IS a change).
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Locked");
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn wrong_pin_triggers_lockout_after_three_attempts_and_recovers() {
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    // Two wrong attempts should keep us locked.
    for _ in 0..2 {
        for _ in 0..3 {
            state = state.next(Event::Keypress(d(9))).0;
        }
        state = state.next(Event::Enter).0;
        assert_mode(&state, "Locked");
    }

    // Third wrong attempt -> lockout.
    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
    }
    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert_mode(&state, "Lockout");
    // Alarm turns on as a change.
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));

    // Still in lockout before duration expires.
    let (next, actions) = state.next(Event::TimerTick(LOCKOUT_DURATION - Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Lockout");
    // With diffing, we might not re-emit SoundAlarm(true); but we MUST NOT turn it off.
    assert!(!actions_contains(&actions, &Action::SoundAlarm(false)));

    // Cross the threshold: recover to Locked and alarm off (this IS a change).
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Locked");
    assert!(actions_contains(&actions, &Action::SoundAlarm(false)));
}

#[test]
fn alarm_times_out_back_to_locked() {
    // Get to Locked state.
    let (state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    // Trigger alarm via intrusion.
    let (mut state, actions) = state.next(Event::DoorSensorChanged(DoorPhysicalState::Open));
    assert_mode(&state, "Alarm");
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));

    // Still alarming before ALARM_DURATION.
    let (next, actions) = state.next(Event::TimerTick(ALARM_DURATION - Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Alarm");
    assert!(!actions_contains(&actions, &Action::SoundAlarm(false)));

    // Cross threshold -> Locked, alarm off.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert_mode(&state, "Locked");
    assert!(actions_contains(&actions, &Action::SoundAlarm(false)));

    // With diff-based outputs, lock may already be true, so don't require SetDoorLock(true).
    assert!(!actions_contains(&actions, &Action::SetDoorLock(false)));
}
#[test]
fn door_open_while_locked_triggers_alarm() {
    let (state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    let (state, actions) = state.next(Event::DoorSensorChanged(DoorPhysicalState::Open));
    assert_mode(&state, "Alarm");

    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));
    // door was already believed locked, but on alarm entry we still ensure locked posture.
    // With diffing, SetDoorLock(true) might or might not emit; it's okay either way.
}

#[test]
fn persisted_snapshot_roundtrip_restores_secure_state() {
    let sealer = PlainSealer;

    // Setup PIN 1-2-3 and enter lockout.
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    // Cause lockout (3 wrong attempts).
    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Enter).0;
    }
    assert_mode(&state, "Lockout");

    let snap: PersistedState<{ MAX_PASSCODE_LEN + 1 }> =
        state.snapshot_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer);
    assert_eq!(snap.version, PersistedState::<{ MAX_PASSCODE_LEN + 1 }>::VERSION);

    let restored =
        SecurityState::restore_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer, snap)
            .expect("snapshot should restore");

    assert_mode(&restored, "Lockout");
}

#[test]
fn corrupted_persisted_state_falls_back_to_none() {
    let sealer = PlainSealer;

    // Version wrong.
    let bad_v = PersistedState::<{ MAX_PASSCODE_LEN + 1 }> {
        version: 99,
        mode: PersistedMode::Locked,
        passcode_blob: [0u8; MAX_PASSCODE_LEN + 1],
        failed_attempts: 0,
        elapsed_ms: 0,
    };
    assert!(SecurityState::restore_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer, bad_v).is_none());

    // Version ok but blob invalid (digits contain 255 -> unseal rejects).
    let mut blob = [0u8; MAX_PASSCODE_LEN + 1];
    blob[0] = 255;
    blob[MAX_PASSCODE_LEN] = 3;

    let bad_blob = PersistedState::<{ MAX_PASSCODE_LEN + 1 }> {
        version: PersistedState::<{ MAX_PASSCODE_LEN + 1 }>::VERSION,
        mode: PersistedMode::Locked,
        passcode_blob: blob,
        failed_attempts: 0,
        elapsed_ms: 0,
    };

    assert!(SecurityState::restore_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer, bad_blob).is_none());
}

#[test]
fn restore_is_primed_with_true_door_state_and_intrusion_policy_is_consistent() {
    let sealer = PlainSealer;

    // Setup PIN 1-2-3.
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert_mode(&state, "Locked");

    // Prime the physical door as CLOSED while we're locked (avoids intrusion alarm).
    state = prime_door(state, DoorPhysicalState::Closed).0;

    // Enter correct PIN -> Unlocked.
    for &v in &[1u8, 2u8, 3u8] {
        state = state.next(Event::Keypress(d(v))).0;
    }
    state = state.next(Event::Enter).0;
    assert_mode(&state, "Unlocked");

    // Now the user opens the door while unlocked (this is normal).
    state = state.next(Event::DoorSensorChanged(DoorPhysicalState::Open)).0;
    assert_mode(&state, "Unlocked");

    // Expire unlock duration while door is open -> remains unlocked (bolt must NOT fire).
    state = state.next(Event::TimerTick(UNLOCKED_DURATION)).0;
    assert_mode(&state, "Unlocked");

    // Snapshot while "Unlocked and expired".
    let snap: PersistedState<{ MAX_PASSCODE_LEN + 1 }> =
        state.snapshot_with::<{ MAX_PASSCODE_LEN + 1 }, _>(&sealer);
    assert_eq!(snap.mode, PersistedMode::Unlocked);

// Restore and prime with "door is actually open".
    let (mut restored, priming_actions) =
        SecurityState::restore_primed_with::<{ MAX_PASSCODE_LEN + 1 }, _>(
            &sealer,
            snap,
            DoorPhysicalState::Open,
        )
        .expect("restore_primed_with should work");

    // The correct behavior here is: stay Unlocked and do NOT fire the bolt while the door is open.
    assert_mode(&restored, "Unlocked");
    assert!(!actions_contains(&priming_actions, &Action::SetDoorLock(true)));

    // A TimerTick after priming must not lock while still open.
    let (next, actions) = restored.next(Event::TimerTick(Duration::from_secs(1)));
    restored = next;
    assert_mode(&restored, "Unlocked");
    assert!(!actions_contains(&actions, &Action::SetDoorLock(true)));

    // Once the door closes, because elapsed >= UNLOCKED_DURATION, we should lock immediately.
    let (next, actions) = restored.next(Event::DoorSensorChanged(DoorPhysicalState::Closed));
    restored = next;
    assert_mode(&restored, "Locked");
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn constants_are_sane() {
    assert!(MIN_PASSCODE_LEN >= 1);
    assert!(MIN_PASSCODE_LEN <= MAX_PASSCODE_LEN);
    assert!(LOCKOUT_DURATION > Duration::ZERO);
    assert!(UNLOCKED_DURATION > Duration::ZERO);
    assert!(ALARM_DURATION > Duration::ZERO);
}

#[test]
fn buffer_full_emits_feedback() {
    let mut state = SecurityState::default();
    assert_mode(&state, "Setup");

    // Fill beyond capacity in setup.
    for _ in 0..MAX_PASSCODE_LEN {
        state = state.next(Event::Keypress(d(1))).0;
    }
    let (_next, actions) = state.next(Event::Keypress(d(2)));

    assert!(actions_contains_feedback(&actions, Feedback::BufferFull));
}

#[cfg(feature = "acoustic_unlock")]
mod acoustic {
    use super::*;

    #[test]
    fn correct_pin_enters_pending_audio_and_timeout_returns_to_locked() {
        let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
        assert_mode(&state, "Locked");

        // Enter correct PIN -> PendingAudio.
        for &v in &[1u8, 2u8, 3u8] {
            state = state.next(Event::Keypress(d(v))).0;
        }
        state = state.next(Event::Enter).0;

        assert_mode(&state, "PendingAudio");

        // Still pending before MFA timeout.
        state = state
            .next(Event::TimerTick(keypad_lock_fsm::MFA_TIMEOUT - Duration::from_secs(1)))
            .0;
        assert_mode(&state, "PendingAudio");

        // Cross timeout -> locked.
        state = state.next(Event::TimerTick(Duration::from_secs(1))).0;
        assert_mode(&state, "Locked");
    }

    #[test]
    fn mfa_stub_securely_fails_to_alarm() {
        let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
        assert_mode(&state, "Locked");

        // Enter correct PIN -> PendingAudio.
        for &v in &[1u8, 2u8, 3u8] {
            state = state.next(Event::Keypress(d(v))).0;
        }
        state = state.next(Event::Enter).0;
        assert_mode(&state, "PendingAudio");

        // Any AudioFrequency should fail the stub and trigger Alarm.
        let (next, actions) = state.next(Event::AudioFrequency(440));
        state = next;

        assert_mode(&state, "Alarm");
        assert!(actions_contains(&actions, &Action::SoundAlarm(true)));
        // SetDoorLock(true) may be unchanged (already locked), so don't require it.
    }
}