use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_keypad-lock-fsm"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn demo_matches_the_readme_transcript() {
    #[cfg(not(feature = "acoustic_unlock"))]
    let expected = include_str!("../docs/demo.txt");
    #[cfg(feature = "acoustic_unlock")]
    let expected = include_str!("../docs/demo-acoustic.txt");
    for args in [&[][..], &["--demo"][..]] {
        let out = run(args);
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
        assert_eq!(String::from_utf8(out.stdout).unwrap(), expected);
    }
}
#[test]
fn cli_help_version_and_bad_arguments_have_meaningful_exit_codes() {
    for args in [&["--help"][..], &["-h"][..], &["--version"][..]] {
        assert!(run(args).status.success());
    }
    for args in [&["--bad"][..], &["--demo", "extra"][..]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8(out.stderr).unwrap().contains("--help"));
    }
}
