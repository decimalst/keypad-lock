use std::time::Duration;

use keypad_lock_fsm::{
    Action, Actions, Digit, DoorPhysicalState, Event, PasscodeBuffer, PersistedMode, PersistedPasscode,
    PersistedState, SecurityState, ALARM_DURATION, LOCKOUT_DURATION, MAX_ACTIONS, MIN_PASSCODE_LEN,
    UNLOCKED_DURATION,
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
fn passcode_buffer_is_bounded_and_clear_zeroes() {
    let mut pb = PasscodeBuffer::default();
    assert_eq!(pb.len(), 0);
    assert!(pb.is_empty());

    for _ in 0..6 {
        assert!(pb.push(d(7)));
    }

    assert_eq!(pb.len(), 6);
    assert!(pb.is_full());
    assert!(!pb.push(d(1)), "push should fail when buffer is full");

    pb.clear();
    assert_eq!(pb.len(), 0);
    assert!(pb.is_empty());
    assert!(!pb.is_full());

    // Verify the backing storage is zeroed by observing the persisted snapshot.
    let snap = SecurityState::Setup { buffer: pb }.snapshot();
    assert_eq!(snap.passcode.len, 0);
    assert!(snap.passcode.digits.iter().all(|&x| x == 0));
}

#[test]
fn setup_requires_min_length_before_locking() {
    let mut state = SecurityState::default();

    // Enter fewer than MIN_PASSCODE_LEN digits and press Enter.
    for &v in &[1u8, 2u8] {
        let (next, actions) = state.next(Event::Keypress(d(v)));
        state = next;
        assert_eq!(actions.len(), 1);
    }

    let (next, actions) = state.next(Event::Enter);
    state = next;

    // Not enough digits: should remain in Setup with no new actions.
    assert!(matches!(state, SecurityState::Setup { .. }));
    assert!(actions.is_empty());

    // Add one more digit and Enter -> should lock.
    let (next, _actions) = state.next(Event::Keypress(d(3)));
    state = next;

    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn empty_enter_in_locked_does_not_increment_failed_attempts() {
    // Setup PIN: 1-2-3
    let (state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

    let (state, _actions) = state.next(Event::Enter);

    match state {
        SecurityState::Locked { failed_attempts, .. } => {
            assert_eq!(failed_attempts, 0, "empty Enter should not count as a failed attempt");
        }
        other => panic!("expected Locked state, got {other:?}"),
    }
}

#[test]
fn correct_pin_unlocks_and_auto_relocks_when_door_closed() {
    // Setup PIN 1-2-3.
    let (mut state, actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert!(actions.contains(&Action::SetDoorLock(true)));

    // Prime: assume door is closed (normal).
    let (s, _acts) = prime_door(state, DoorPhysicalState::Closed);
    state = s;

    // Enter correct PIN.
    for &v in &[1u8, 2u8, 3u8] {
        let (next, _actions) = state.next(Event::Keypress(d(v)));
        state = next;
    }

    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert!(matches!(state, SecurityState::Unlocked { .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(false)));

    // Tick less than UNLOCKED_DURATION -> still unlocked.
    let (next, actions) = state.next(Event::TimerTick(UNLOCKED_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Unlocked { .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(false)));

    // Cross the threshold while door is closed -> re-lock.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn wrong_pin_triggers_lockout_after_three_attempts_and_recovers() {
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

    // Attempt 1: 9-9-9
    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
    }
    state = state.next(Event::Enter).0;

    match state {
        SecurityState::Locked { failed_attempts, .. } => assert_eq!(failed_attempts, 1),
        other => panic!("expected Locked after first failure, got {other:?}"),
    }

    // Attempt 2: 9-9-9
    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
    }
    state = state.next(Event::Enter).0;

    match state {
        SecurityState::Locked { failed_attempts, .. } => assert_eq!(failed_attempts, 2),
        other => panic!("expected Locked after second failure, got {other:?}"),
    }

    // Attempt 3: 9-9-9 -> lockout
    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
    }
    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert!(matches!(state, SecurityState::Lockout { .. }));
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));

    // Still in lockout before duration expires.
    let (next, actions) = state.next(Event::TimerTick(LOCKOUT_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Lockout { .. }));
    // Idempotent assertions during lockout.
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));

    // Cross the threshold: recover to Locked.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { failed_attempts: 0, .. }));
    assert!(actions_contains(&actions, &Action::SoundAlarm(false)));
}

#[test]
fn alarm_times_out_back_to_locked() {
    // Construct an Alarm state directly.
    let mut passcode = PasscodeBuffer::default();
    for &v in &[1u8, 2u8, 3u8] {
        let _ = passcode.push(d(v));
    }

    let mut state = SecurityState::Alarm {
        passcode,
        elapsed: Duration::ZERO,
    };

    // Still alarming before ALARM_DURATION.
    let (next, actions) = state.next(Event::TimerTick(ALARM_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Alarm { .. }));
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));

    // Cross the threshold -> Locked.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions_contains(&actions, &Action::SoundAlarm(false)));
}

#[test]
fn door_open_while_locked_triggers_alarm() {
    // Setup PIN 1-2-3.
    let (state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert!(matches!(state, SecurityState::Locked { .. }));

    let (state, actions) = state.next(Event::DoorSensorChanged(DoorPhysicalState::Open));

    assert!(matches!(state, SecurityState::Alarm { .. }));
    assert!(actions_contains(&actions, &Action::SoundAlarm(true)));
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn persisted_snapshot_roundtrip_restores_secure_state() {
    // Setup PIN 1-2-3 and enter lockout.
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

    for _ in 0..3 {
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Keypress(d(9))).0;
        state = state.next(Event::Enter).0;
    }
    assert!(matches!(state, SecurityState::Lockout { .. }));

    let snap = state.snapshot();
    assert_eq!(snap.version, PersistedState::VERSION);

    let restored = SecurityState::restore(snap).expect("snapshot should restore");
    assert!(matches!(restored, SecurityState::Lockout { .. }));
}

#[test]
fn corrupted_persisted_state_falls_back_to_default() {
    let mut bad = PersistedState {
        version: 99,
        mode: PersistedMode::Locked,
        passcode: PersistedPasscode {
            digits: [255u8; keypad_lock_fsm::MAX_PASSCODE_LEN],
            len: 7,
        },
        failed_attempts: 250,
        elapsed_ms: u32::MAX,
    };

    assert!(SecurityState::restore(bad).is_none());

    // Fix version but keep invalid digits.
    bad.version = PersistedState::VERSION;
    assert!(SecurityState::restore(bad).is_none());
}

#[test]
fn restore_is_primed_with_true_door_state_to_prevent_locking_open() {
    // Build a persisted snapshot representing "Unlocked and expired" (elapsed >= UNLOCKED_DURATION).
    // After restore, we MUST prime with DoorSensorChanged(Open) before TimerTick to avoid firing bolt.

    let mut passcode = PasscodeBuffer::default();
    for &v in &[1u8, 2u8, 3u8] {
        let _ = passcode.push(d(v));
    }

    // Create a snapshot in Unlocked mode with elapsed beyond duration.
    let snap = SecurityState::Unlocked {
        passcode,
        elapsed: UNLOCKED_DURATION,
        door: DoorPhysicalState::Closed, // placeholder; restore will not persist door
    }
    .snapshot();

    // Restore and prime with "door is actually open".
    let (mut state, priming_actions) =
        SecurityState::restore_primed(snap, DoorPhysicalState::Open).expect("restore_primed should work");

    // Priming should *not* lock the door.
    assert!(!actions_contains(&priming_actions, &Action::SetDoorLock(true)));

    // Now, if a TimerTick arrives, the FSM should refuse to lock while open.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Unlocked { door: DoorPhysicalState::Open, .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(false)));
    assert!(!actions_contains(&actions, &Action::SetDoorLock(true)));

    // Once the door closes, we should lock immediately (because elapsed >= duration).
    let (next, actions) = state.next(Event::DoorSensorChanged(DoorPhysicalState::Closed));
    state = next;
    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
}

#[test]
fn constants_are_sane() {
    assert!(MIN_PASSCODE_LEN >= 1);
    assert!(MIN_PASSCODE_LEN as usize <= keypad_lock_fsm::MAX_PASSCODE_LEN);
    assert!(LOCKOUT_DURATION > Duration::ZERO);
    assert!(UNLOCKED_DURATION > Duration::ZERO);
    assert!(ALARM_DURATION > Duration::ZERO);
}

#[cfg(feature = "acoustic_unlock")]
mod acoustic {
    use super::*;

    #[test]
    fn correct_pin_enters_pending_audio_and_timeout_returns_to_locked() {
        let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

        // Enter correct PIN.
        for &v in &[1u8, 2u8, 3u8] {
            let (next, _actions) = state.next(Event::Keypress(d(v)));
            state = next;
        }
        let (next, _actions) = state.next(Event::Enter);
        state = next;

        assert!(matches!(state, SecurityState::PendingAudio { .. }));

        // Still pending before MFA timeout.
        let (next, _actions) =
            state.next(Event::TimerTick(keypad_lock_fsm::MFA_TIMEOUT - Duration::from_secs(1)));
        state = next;
        assert!(matches!(state, SecurityState::PendingAudio { .. }));

        // Cross timeout -> locked.
        let (next, _actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
        state = next;
        assert!(matches!(state, SecurityState::Locked { .. }));
    }

    #[test]
    fn mfa_stub_securely_fails_to_alarm() {
        let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

        // Enter correct PIN -> PendingAudio.
        for &v in &[1u8, 2u8, 3u8] {
            let (next, _actions) = state.next(Event::Keypress(d(v)));
            state = next;
        }
        let (next, _actions) = state.next(Event::Enter);
        state = next;
        assert!(matches!(state, SecurityState::PendingAudio { .. }));

        // Any AudioFrequency should fail the stub and trigger Alarm.
        let (next, actions) = state.next(Event::AudioFrequency(440));
        state = next;

        assert!(matches!(state, SecurityState::Alarm { .. }));
        assert!(actions_contains(&actions, &Action::SoundAlarm(true)));
        assert!(actions_contains(&actions, &Action::SetDoorLock(true)));
    }
}