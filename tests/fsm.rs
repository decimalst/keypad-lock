use std::time::Duration;

use keypad_lock_fsm::{Action, Digit, Event, PasscodeBuffer, SecurityState, ALARM_DURATION, LOCKOUT_DURATION, MIN_PASSCODE_LEN, UNLOCKED_DURATION};

fn d(v: u8) -> Digit {
    Digit::new(v).unwrap()
}

fn enter_passcode(state: SecurityState, digits: &[u8]) -> (SecurityState, Vec<Action>) {
    let mut s = state;
    let mut all_actions = Vec::new();

    for &v in digits {
        let (next, actions) = s.next(Event::Keypress(d(v)));
        s = next;
        all_actions.extend(actions);
    }

    let (next, actions) = s.next(Event::Enter);
    s = next;
    all_actions.extend(actions);

    (s, all_actions)
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

    // After clear, the buffer should be structurally equal to default.
    assert_eq!(pb, PasscodeBuffer::default());
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
    assert!(actions.contains(&Action::SetDoorLock(true)));
}

#[test]
fn empty_enter_in_locked_does_not_increment_failed_attempts() {
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
fn correct_pin_unlocks_and_auto_relocks() {
    // Setup PIN 1-2-3.
    let (mut state, actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);
    assert!(actions.contains(&Action::SetDoorLock(true)));

    // Enter correct PIN.
    let (next, _actions) = state.next(Event::Keypress(d(1)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(2)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(3)));
    state = next;

    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert!(matches!(state, SecurityState::Unlocked { .. }));
    assert!(actions.contains(&Action::SetDoorLock(false)));

    // Tick less than UNLOCKED_DURATION -> still unlocked.
    let (next, actions) = state.next(Event::TimerTick(UNLOCKED_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Unlocked { .. }));
    assert!(actions.contains(&Action::SetDoorLock(false)));

    // Cross the threshold -> re-lock.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions.contains(&Action::SetDoorLock(true)));
}

#[test]
fn wrong_pin_triggers_lockout_after_three_attempts_and_recovers() {
    let (mut state, _actions) = enter_passcode(SecurityState::default(), &[1, 2, 3]);

    // Attempt 1: 9-9-9
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Enter);
    state = next;

    match state {
        SecurityState::Locked { failed_attempts, .. } => assert_eq!(failed_attempts, 1),
        other => panic!("expected Locked after first failure, got {other:?}"),
    }

    // Attempt 2: 9-9-9
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Enter);
    state = next;

    match state {
        SecurityState::Locked { failed_attempts, .. } => assert_eq!(failed_attempts, 2),
        other => panic!("expected Locked after second failure, got {other:?}"),
    }

    // Attempt 3: 9-9-9 -> lockout
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, _actions) = state.next(Event::Keypress(d(9)));
    state = next;
    let (next, actions) = state.next(Event::Enter);
    state = next;

    assert!(matches!(state, SecurityState::Lockout { .. }));
    assert!(actions.contains(&Action::SoundAlarm(true)));

    // Still in lockout before duration expires.
    let (next, actions) = state.next(Event::TimerTick(LOCKOUT_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Lockout { .. }));
    // Idempotent assertions during lockout.
    assert!(actions.contains(&Action::SoundAlarm(true)));
    assert!(actions.contains(&Action::SetDoorLock(true)));

    // Cross the threshold: recover to Locked.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { failed_attempts: 0, .. }));
    assert!(actions.contains(&Action::SoundAlarm(false)));
}

#[test]
fn alarm_times_out_back_to_locked() {
    // Construct an Alarm state directly.
    let mut passcode = PasscodeBuffer::default();
    for &v in &[1u8, 2u8, 3u8] {
        passcode.push(d(v));
    }

    let mut state = SecurityState::Alarm {
        passcode,
        elapsed: Duration::ZERO,
    };

    // Still alarming before ALARM_DURATION.
    let (next, actions) = state.next(Event::TimerTick(ALARM_DURATION - Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Alarm { .. }));
    assert!(actions.contains(&Action::SoundAlarm(true)));

    // Cross the threshold -> Locked.
    let (next, actions) = state.next(Event::TimerTick(Duration::from_secs(1)));
    state = next;
    assert!(matches!(state, SecurityState::Locked { .. }));
    assert!(actions.contains(&Action::SoundAlarm(false)));
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
        let (next, _actions) = state.next(Event::TimerTick(keypad_lock_fsm::MFA_TIMEOUT - Duration::from_secs(1)));
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
        assert!(actions.contains(&Action::SoundAlarm(true)));
        assert!(actions.contains(&Action::SetDoorLock(true)));
    }
}
