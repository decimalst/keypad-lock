# Suggested LinkedIn post

I revisited my Rust keypad-lock project with a focus on making the engineering easy to inspect and reproduce.

The core is a deterministic, allocation-free `no_std` state machine. It decides what should happen; hardware adapters own the actual bolt, alarm, display and storage.

The review uncovered useful edge cases: a long PIN could authenticate through a truncated prefix, intrusion alarms could reset the retry budget, and startup needed explicit output synchronization. Each now has regression coverage.

I added an independent policy model that checks 7,776 operation histories in each feature configuration, embedded ARM compilation, automated quality checks, and a demo that runs without hardware or real-time waits.

The most useful part was making the boundaries honest: this is tested lock logic, with production cryptography and physical hardware validation still belonging to the integration layer.

Code, architecture diagram and reproducible demo:
https://github.com/decimalst/keypad-lock

#Rust #EmbeddedSystems #SoftwareEngineering #Testing

---

Attach `docs/assets/architecture.png` or `docs/assets/demo.png`. This is a suggested caption; no post has been published.
