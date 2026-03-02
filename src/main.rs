use std::time::Duration;

use keypad_lock_fsm::{Digit, Event, SecurityState};

fn main() {
    // Tiny deterministic demo script (no IO). This keeps the binary simple and
    // the core FSM purely in the library.

    let mut state = SecurityState::default();

    let script = [
        // Setup PIN: 1-2-3 then Enter
        Event::Keypress(Digit::new(1).unwrap()),
        Event::Keypress(Digit::new(2).unwrap()),
        Event::Keypress(Digit::new(3).unwrap()),
        Event::Enter,
        // Try to unlock: 1-2-3 then Enter
        Event::Keypress(Digit::new(1).unwrap()),
        Event::Keypress(Digit::new(2).unwrap()),
        Event::Keypress(Digit::new(3).unwrap()),
        Event::Enter,
        // Simulate time passing to auto re-lock
        Event::TimerTick(Duration::from_secs(11)),
    ];

    for ev in script {
        let (next, actions) = state.next(ev);
        state = next;

        for a in actions {
            println!("Action: {a:?}");
        }
    }

    println!("Final state: {state:?}");
}
