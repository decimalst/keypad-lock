//! Reproducible host-side demonstration; no device or credentials required.
use keypad_lock_fsm::{Action, Digit, DoorPhysicalState, Event, SecurityState};
use std::{env, process::ExitCode, time::Duration};

struct Demo {
    state: SecurityState,
    step: usize,
}
impl Demo {
    fn new() -> Self {
        Self {
            state: SecurityState::default(),
            step: 0,
        }
    }
    fn event(&mut self, event: Event) {
        let state = core::mem::take(&mut self.state);
        self.state = state.next(event).0;
    }
    fn pin(&mut self, digits: &[u8]) {
        for &digit in digits {
            self.event(Event::Keypress(Digit::new(digit).expect("demo digit")));
        }
        self.event(Event::Enter);
    }
    fn show(&mut self, label: &str) {
        let actions = self.state.output_actions();
        let locked = actions.iter().any(|a| *a == Action::SetDoorLock(true));
        let alarm = actions.iter().any(|a| *a == Action::SoundAlarm(true));
        println!(
            "{:02}  {:<34} {:<12} bolt={:<8} alarm={}",
            self.step,
            label,
            format!("{:?}", self.state.mode()),
            if locked { "LOCKED" } else { "RELEASED" },
            if alarm { "ON" } else { "off" }
        );
        self.step += 1;
    }
    fn run(mut self) {
        println!("KEYPAD LOCK / deterministic Rust demo");
        println!("No hardware. No sleeps. PIN input stays redacted.\n");
        self.show("Boot / synchronize outputs");
        self.pin(&[1, 2, 3]);
        self.show("Enroll a demonstration PIN");
        self.pin(&[9, 9, 9]);
        self.show("Reject an incorrect PIN");
        self.pin(&[1, 2, 3]);
        self.show("Accept the correct PIN");
        #[cfg(not(feature = "acoustic_unlock"))]
        {
            self.event(Event::DoorSensorChanged(DoorPhysicalState::Open));
            self.show("Door opens");
            self.event(Event::TimerTick(Duration::from_secs(10)));
            self.show("10s / open door inhibits bolt");
            self.event(Event::DoorSensorChanged(DoorPhysicalState::Closed));
            self.show("Door closes / relock");
        }
        #[cfg(feature = "acoustic_unlock")]
        {
            self.event(Event::AudioFrequency(440));
            self.show("Unverified audio / deny");
            self.event(Event::TimerTick(Duration::from_secs(5)));
            self.show("5s / alarm expires");
        }
        for _ in 0..3 {
            self.pin(&[9, 9, 9]);
        }
        self.show("Three failures / lockout");
        self.pin(&[1, 2, 3]);
        self.show("Correct PIN ignored in lockout");
        self.event(Event::TimerTick(Duration::from_secs(30)));
        self.show("30s / retry window resets");
        self.event(Event::DoorSensorChanged(DoorPhysicalState::Open));
        self.show("Forced opening / alarm");
        self.event(Event::DoorSensorChanged(DoorPhysicalState::Closed));
        self.event(Event::TimerTick(Duration::from_secs(5)));
        self.show("Door closed / alarm expires");
        println!("\nAll transitions use the same no_std library as an embedded adapter.");
    }
}
fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => Demo::new().run(),
        [arg] if arg == "--demo" => Demo::new().run(),
        [arg] if arg == "--help" || arg == "-h" => println!(
            "keypad-lock-fsm [--demo | --help | --version]\nRun a deterministic, hardware-free lock simulation."
        ),
        [arg] if arg == "--version" => println!("keypad-lock-fsm {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("Unknown arguments. Use --help.");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
