use std::time::Duration;

use keypad_lock_fsm::{Digit, Event, SecurityState};

fn main() {
    let mut state = SecurityState::default();

    let script = [
        Event::Keypress(Digit::new(1).unwrap()),
        Event::Keypress(Digit::new(2).unwrap()),
        Event::Keypress(Digit::new(3).unwrap()),
        Event::Enter,
        Event::Keypress(Digit::new(1).unwrap()),
        Event::Keypress(Digit::new(2).unwrap()),
        Event::Keypress(Digit::new(3).unwrap()),
        Event::Enter,
        Event::TimerTick(Duration::from_secs(11)),
    ];

    for ev in script {
        let (next, actions) = state.next(ev);
        state = next;

        for a in actions.iter() {
            println!("Action: {a:?}");
        }
    }

    println!("Final state: {state:?}");
}