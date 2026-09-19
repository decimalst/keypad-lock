use core::time::Duration;
use keypad_lock_fsm::*;

// Intentionally plaintext fixture; never suitable for device storage.
struct Fixture;
impl PasscodeSealer<7> for Fixture {
    fn seal(&self, digits: [u8; 6], len: u8) -> [u8; 7] {
        let mut blob = [0; 7];
        blob[..6].copy_from_slice(&digits);
        blob[6] = len;
        blob
    }
    fn unseal(&self, blob: [u8; 7]) -> Option<([u8; 6], u8)> {
        Some((blob[..6].try_into().unwrap(), blob[6]))
    }
}
fn submit(mut state: SecurityState, pin: &[u8]) -> (SecurityState, Actions<MAX_ACTIONS>) {
    for &digit in pin {
        state = state.next(Event::Keypress(Digit::new(digit).unwrap())).0;
    }
    state.next(Event::Enter)
}
fn locked() -> SecurityState {
    submit(SecurityState::default(), &[1, 2, 3]).0
}
fn snapshot(mode: PersistedMode, elapsed_ms: u32) -> PersistedState<7> {
    PersistedState {
        version: PersistedState::<7>::VERSION,
        mode,
        passcode_blob: if mode == PersistedMode::Setup {
            [0; 7]
        } else {
            [1, 2, 3, 0, 0, 0, 3]
        },
        failed_attempts: if mode == PersistedMode::Lockout {
            LOCKOUT_THRESHOLD
        } else {
            0
        },
        elapsed_ms,
    }
}
fn restore(mode: PersistedMode, elapsed_ms: u32) -> SecurityState {
    SecurityState::restore_primed_with(
        &Fixture,
        snapshot(mode, elapsed_ms),
        DoorPhysicalState::Closed,
    )
    .unwrap()
    .0
}
fn has(actions: &Actions<MAX_ACTIONS>, action: Action) -> bool {
    actions.iter().any(|a| a == &action)
}

#[test]
fn overlong_pin_never_authenticates_its_valid_prefix() {
    let state = submit(SecurityState::default(), &[1, 2, 3, 4, 5, 6]).0;
    let (state, actions) = submit(state, &[1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(state.mode(), PersistedMode::Locked);
    assert!(has(&actions, Action::Feedback(Feedback::IncorrectPin)));
    let state = state.next(Event::Clear).0;
    let (_, actions) = submit(state, &[1, 2, 3, 4, 5, 6]);
    assert!(has(&actions, Action::Feedback(Feedback::PinAccepted)));
}
#[test]
fn overlong_setup_requires_clear_and_does_not_commit_truncated_pin() {
    let (state, actions) = submit(SecurityState::default(), &[1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(state.mode(), PersistedMode::Setup);
    assert!(has(&actions, Action::Feedback(Feedback::BufferFull)));
    let state = state.next(Event::Clear).0;
    assert_eq!(submit(state, &[9, 8, 7]).0.mode(), PersistedMode::Locked);
}
#[test]
fn buffers_compare_length_digits_and_overflow_without_accepting_empty() {
    let mut a = PasscodeBuffer::default();
    let mut b = PasscodeBuffer::default();
    assert!(!a.matches(&b));
    for d in [0, 1, 2] {
        assert!(a.push(Digit::new(d).unwrap()));
        assert!(b.push(Digit::new(d).unwrap()));
    }
    assert!(a.matches(&b));
    assert!(b.push(Digit::new(0).unwrap()));
    assert!(!a.matches(&b));
    a.clear();
    assert!(!a.matches(&b));
}
#[test]
fn boot_and_restore_explicitly_synchronize_every_output() {
    let actions = SecurityState::default().output_actions();
    assert_eq!(
        actions.into_iter().collect::<Vec<_>>(),
        vec![
            Action::SetDoorLock(true),
            Action::SoundAlarm(false),
            Action::UpdateDisplayLen(0)
        ]
    );
    for mode in [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Lockout,
        PersistedMode::Alarm,
        PersistedMode::Unlocked,
    ] {
        let (state, actions) = SecurityState::restore_primed_with(
            &Fixture,
            snapshot(mode, 0),
            DoorPhysicalState::Closed,
        )
        .unwrap();
        assert_eq!(actions.len(), 3);
        assert!(has(
            &actions,
            Action::SetDoorLock(mode != PersistedMode::Unlocked)
        ));
        assert_eq!(state.output_actions(), actions);
        assert!(state.next(Event::TimerTick(Duration::ZERO)).1.is_empty());
    }
}
#[test]
fn restore_rejects_invalid_pin_lengths_and_digits_for_every_mode() {
    for mode in [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Lockout,
        PersistedMode::Unlocked,
        PersistedMode::Alarm,
    ] {
        for len in 0..=255 {
            let mut snap = snapshot(mode, 0);
            snap.passcode_blob[6] = len;
            let valid = if mode == PersistedMode::Setup {
                len == 0
            } else {
                (3..=6).contains(&len)
            };
            assert_eq!(
                SecurityState::restore_with(&Fixture, snap).is_some(),
                valid,
                "{mode:?} len={len}"
            );
        }
    }
    let mut snap = snapshot(PersistedMode::Locked, 0);
    snap.passcode_blob[0] = 10;
    assert!(SecurityState::restore_with(&Fixture, snap).is_none());
    snap.passcode_blob = [1, 2, 3, 255, 255, 255, 3];
    let restored = SecurityState::restore_with(&Fixture, snap).unwrap();
    assert_eq!(
        restored.snapshot_with(&Fixture).passcode_blob,
        [1, 2, 3, 0, 0, 0, 3]
    );
}
#[test]
fn snapshot_validation_rejects_impossible_metadata() {
    for mode in [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Lockout,
        PersistedMode::Unlocked,
        PersistedMode::Alarm,
    ] {
        for failures in 0..=255 {
            for time in [0, 1, u32::MAX] {
                let mut snap = snapshot(mode, time);
                snap.failed_attempts = failures;
                let valid = match mode {
                    PersistedMode::Setup => failures == 0 && time == 0,
                    PersistedMode::Locked => failures < 3 && time == 0,
                    PersistedMode::Lockout => failures == 3,
                    PersistedMode::Alarm => failures < 3,
                    _ => failures == 0,
                };
                assert_eq!(snap.validate_strict(), valid);
            }
        }
    }
    let mut snap = snapshot(PersistedMode::Locked, 0);
    snap.version = 2;
    assert!(!snap.validate_strict());
}
#[test]
fn setup_input_is_not_persisted_and_guess_is_not_restored() {
    let state = SecurityState::default()
        .next(Event::Keypress(Digit::new(9).unwrap()))
        .0;
    assert_eq!(state.snapshot_with(&Fixture).passcode_blob, [0; 7]);
    let state = locked().next(Event::Keypress(Digit::new(1).unwrap())).0;
    let state = SecurityState::restore_with(&Fixture, state.snapshot_with(&Fixture)).unwrap();
    assert!(state.next(Event::Enter).1.is_empty());
}
#[test]
fn intrusion_alarm_does_not_reset_failed_attempts_even_across_reboot() {
    let state = submit(locked(), &[9, 9, 9]).0;
    let state = submit(state, &[9, 9, 9]).0;
    let state = state
        .next(Event::DoorSensorChanged(DoorPhysicalState::Open))
        .0;
    let snap = state.snapshot_with(&Fixture);
    assert_eq!(snap.failed_attempts, 2);
    let state = SecurityState::restore_primed_with(&Fixture, snap, DoorPhysicalState::Closed)
        .unwrap()
        .0;
    let state = state.next(Event::TimerTick(ALARM_DURATION)).0;
    assert_eq!(submit(state, &[9, 9, 9]).0.mode(), PersistedMode::Lockout);
}
#[test]
fn unprimed_restore_waits_for_live_closed_sensor_before_relocking() {
    let state =
        SecurityState::restore_with(&Fixture, snapshot(PersistedMode::Unlocked, 0)).unwrap();
    let (state, actions) = state.next(Event::TimerTick(Duration::MAX));
    assert_eq!(state.mode(), PersistedMode::Unlocked);
    assert!(!has(&actions, Action::SetDoorLock(true)));
    let (state, actions) = state.next(Event::DoorSensorChanged(DoorPhysicalState::Closed));
    assert_eq!(state.mode(), PersistedMode::Locked);
    assert!(has(&actions, Action::SetDoorLock(true)));
}
#[test]
fn timer_boundaries_and_extreme_durations_are_safe() {
    for (mode, limit) in [
        (PersistedMode::Lockout, LOCKOUT_DURATION),
        (PersistedMode::Alarm, ALARM_DURATION),
        (PersistedMode::Unlocked, UNLOCKED_DURATION),
    ] {
        for dt in [
            Duration::ZERO,
            limit - Duration::from_nanos(1),
            limit,
            Duration::MAX,
        ] {
            let state = restore(mode, 0).next(Event::TimerTick(dt)).0;
            assert_eq!(
                state.mode(),
                if dt >= limit {
                    PersistedMode::Locked
                } else {
                    mode
                }
            );
        }
        let state = restore(mode, 1).next(Event::TimerTick(Duration::MAX)).0;
        assert_eq!(state.mode(), PersistedMode::Locked);
    }
}
#[test]
fn non_timer_events_do_not_bypass_lockout_or_alarm() {
    let events = [
        Event::Keypress(Digit::new(8).unwrap()),
        Event::Enter,
        Event::Clear,
        Event::DoorSensorChanged(DoorPhysicalState::Open),
        Event::DoorSensorChanged(DoorPhysicalState::Closed),
        #[cfg(feature = "acoustic_unlock")]
        Event::AudioFrequency(440),
    ];
    for mode in [PersistedMode::Lockout, PersistedMode::Alarm] {
        for event in &events {
            let (state, actions) = restore(mode, 0).next(event.clone());
            assert_eq!(state.mode(), mode);
            assert!(actions.is_empty());
        }
    }
}
#[test]
fn idle_inputs_preserve_setup_locked_and_unlocked_modes() {
    for mode in [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Unlocked,
    ] {
        for event in [
            Event::Clear,
            Event::TimerTick(Duration::ZERO),
            Event::DoorSensorChanged(DoorPhysicalState::Closed),
        ] {
            let (state, actions) = restore(mode, 0).next(event);
            assert_eq!(state.mode(), mode);
            assert!(actions.is_empty());
        }
    }
    for event in [
        Event::Clear,
        Event::Enter,
        Event::Keypress(Digit::new(4).unwrap()),
    ] {
        let (state, actions) = restore(PersistedMode::Unlocked, 0).next(event);
        assert_eq!(state.mode(), PersistedMode::Unlocked);
        assert!(actions.is_empty());
    }
}
#[test]
fn actions_capacity_and_borrowed_owned_iteration_agree() {
    let mut actions = Actions::<2>::default();
    assert!(actions.push(Action::SoundAlarm(true)));
    assert!(actions.push_debug(Action::SetDoorLock(true)));
    assert!(!actions.push(Action::SoundAlarm(false)));
    assert_eq!(actions.len(), 2);
    assert_eq!(
        (&actions).into_iter().cloned().collect::<Vec<_>>(),
        actions.clone().into_iter().collect::<Vec<_>>()
    );
    assert!(!Actions::<0>::default().push(Action::SoundAlarm(true)));
}
#[test]
#[should_panic(expected = "Actions overflow")]
fn internal_action_overflow_is_never_silent_in_release() {
    let _ = Actions::<0>::default().push_debug(Action::SoundAlarm(true));
}
#[test]
fn digit_conversion_exhaustively_checks_the_byte_domain() {
    for value in 0..=255 {
        assert_eq!(Digit::try_from(value).is_ok(), value <= 9);
    }
}
#[test]
fn secret_debug_output_is_redacted() {
    let state = submit(SecurityState::default(), &[9, 8, 7, 6, 5, 4]).0;
    let debug = format!("{state:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("9, 8, 7, 6, 5, 4"));
}
#[test]
fn rejected_unseal_never_restores_a_state() {
    struct Reject;
    impl PasscodeSealer<7> for Reject {
        fn seal(&self, _: [u8; 6], _: u8) -> [u8; 7] {
            [0; 7]
        }
        fn unseal(&self, _: [u8; 7]) -> Option<([u8; 6], u8)> {
            None
        }
    }
    assert!(
        SecurityState::restore_primed_with(
            &Reject,
            snapshot(PersistedMode::Locked, 0),
            DoorPhysicalState::Closed
        )
        .is_none()
    );
}
#[cfg(feature = "acoustic_unlock")]
#[test]
fn acoustic_input_never_authenticates_and_intrusion_alarms_while_pending() {
    for frequency in [0, 1, 440, 1000, u32::MAX] {
        let state = submit(locked(), &[1, 2, 3]).0;
        let snap = state.snapshot_with(&Fixture);
        assert_eq!(snap.mode, PersistedMode::PendingAudio);
        let state = SecurityState::restore_with(&Fixture, snap).unwrap();
        assert_eq!(
            state.next(Event::AudioFrequency(frequency)).0.mode(),
            PersistedMode::Alarm
        );
    }
    assert_eq!(
        submit(locked(), &[1, 2, 3])
            .0
            .next(Event::DoorSensorChanged(DoorPhysicalState::Open))
            .0
            .mode(),
        PersistedMode::Alarm
    );
    for event in [
        Event::Clear,
        Event::Enter,
        Event::Keypress(Digit::new(4).unwrap()),
        Event::DoorSensorChanged(DoorPhysicalState::Closed),
    ] {
        let (state, actions) = submit(locked(), &[1, 2, 3]).0.next(event);
        assert_eq!(state.mode(), PersistedMode::PendingAudio);
        assert!(actions.is_empty());
    }
    for mode in [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Unlocked,
    ] {
        let (state, actions) = restore(mode, 0).next(Event::AudioFrequency(440));
        assert_eq!(state.mode(), mode);
        assert!(actions.is_empty());
    }
}

#[test]
fn all_five_operation_sequences_agree_with_an_independent_policy_model() {
    // 6^5 = 7,776 histories; the model operates on whole user operations, not
    // implementation fields or transition code. Each prefix is checked.
    for encoded in 0u32..6u32.pow(5) {
        let mut code = encoded;
        let mut state = locked();
        let mut mode = PersistedMode::Locked;
        let mut failures = 0;
        for _ in 0..5 {
            let op = code % 6;
            code /= 6;
            match op {
                0 | 1 => {
                    state = submit(state, if op == 0 { &[9, 9, 9] } else { &[1, 2, 3] }).0;
                    if mode == PersistedMode::Locked {
                        if op == 0 {
                            failures += 1;
                            if failures == 3 {
                                mode = PersistedMode::Lockout;
                            }
                        } else {
                            failures = 0;
                            mode = if cfg!(feature = "acoustic_unlock") {
                                pending_mode()
                            } else {
                                PersistedMode::Unlocked
                            };
                        }
                    }
                }
                2 => {
                    state = state.next(Event::Enter).0;
                }
                3 => {
                    state = state.next(Event::Keypress(Digit::new(8).unwrap())).0;
                    state = state.next(Event::Clear).0;
                }
                4 => {
                    state = state.next(Event::TimerTick(Duration::from_secs(30))).0;
                    if mode != PersistedMode::Locked {
                        if mode != PersistedMode::Alarm {
                            failures = 0;
                        }
                        mode = PersistedMode::Locked;
                    }
                }
                _ => {
                    state = state
                        .next(Event::DoorSensorChanged(DoorPhysicalState::Open))
                        .0;
                    state = state
                        .next(Event::DoorSensorChanged(DoorPhysicalState::Closed))
                        .0;
                    if mode == PersistedMode::Locked || mode == pending_mode() {
                        mode = PersistedMode::Alarm;
                    }
                }
            }
            assert_eq!(state.mode(), mode, "history={encoded} op={op}");
            assert_eq!(
                state.snapshot_with(&Fixture).failed_attempts,
                failures,
                "history={encoded}"
            );
            assert!(has(
                &state.output_actions(),
                Action::SetDoorLock(mode != PersistedMode::Unlocked)
            ));
            assert!(has(
                &state.output_actions(),
                Action::SoundAlarm(matches!(
                    mode,
                    PersistedMode::Alarm | PersistedMode::Lockout
                ))
            ));
        }
    }
}
fn pending_mode() -> PersistedMode {
    #[cfg(feature = "acoustic_unlock")]
    {
        PersistedMode::PendingAudio
    }
    #[cfg(not(feature = "acoustic_unlock"))]
    {
        PersistedMode::Setup
    } // unreachable in this model after enrollment
}
#[test]
fn event_debug_never_prints_input_digits() {
    assert_eq!(
        format!("{:?}", Event::Keypress(Digit::new(8).unwrap())),
        "Keypress([REDACTED])"
    );
    for event in [
        Event::Enter,
        Event::Clear,
        Event::TimerTick(Duration::ZERO),
        Event::DoorSensorChanged(DoorPhysicalState::Closed),
    ] {
        assert!(!format!("{event:?}").is_empty());
    }
    #[cfg(feature = "acoustic_unlock")]
    assert_eq!(
        format!("{:?}", Event::AudioFrequency(123456)),
        "AudioFrequency([REDACTED])"
    );
}

#[test]
fn every_durable_mode_roundtrips_including_expired_timers() {
    let modes = [
        PersistedMode::Setup,
        PersistedMode::Locked,
        PersistedMode::Lockout,
        PersistedMode::Unlocked,
        PersistedMode::Alarm,
        #[cfg(feature = "acoustic_unlock")]
        PersistedMode::PendingAudio,
    ];
    for &mode in &modes {
        let time = if matches!(mode, PersistedMode::Setup | PersistedMode::Locked) {
            0
        } else {
            u32::MAX
        };
        let snap = snapshot(mode, time);
        let state = SecurityState::restore_with(&Fixture, snap).unwrap();
        assert_eq!(state.snapshot_with(&Fixture), snap);
    }
}
