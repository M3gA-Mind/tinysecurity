use super::*;

fn subject(name: &str) -> SubjectScope {
    SubjectScope {
        user: name.into(),
        workspace: "w".into(),
        agent: "a".into(),
    }
}
const FIRST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECOND: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn malformed_streams_never_pin() {
    let pins = StreamPins::default();
    for stream in ["", "short", &"g".repeat(32), &"a".repeat(33)] {
        assert!(matches!(
            pins.pin(&subject("u"), stream),
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn a_subject_keeps_one_stream_while_live_and_through_the_retention_window() {
    let pins = StreamPins::default();
    let user = subject("u");
    assert!(pins.pin(&user, FIRST).is_ok());
    assert!(pins.pin(&user, FIRST).is_ok());
    assert!(matches!(pins.pin(&user, SECOND), Err(Error::Conflict)));
    assert!(pins.unpin(&user).is_ok());
    assert!(matches!(pins.pin(&user, SECOND), Err(Error::Conflict)));
    assert!(pins.pin(&user, FIRST).is_ok());
    // Other subjects are independent.
    assert!(pins.pin(&subject("other"), SECOND).is_ok());
}

#[test]
fn a_released_pin_is_reclaimed_after_the_window_and_the_table_is_bounded() {
    let mut pins = StreamPins {
        max: 1,
        ..StreamPins::default()
    };
    let (first, second) = (subject("a"), subject("b"));
    assert!(pins.pin(&first, FIRST).is_ok());
    assert!(matches!(pins.pin(&second, FIRST), Err(Error::Unavailable)));
    assert!(pins.unpin(&first).is_ok());
    assert!(matches!(pins.pin(&second, FIRST), Err(Error::Unavailable)));
    pins.ttl = Duration::ZERO;
    assert!(pins.pin(&second, FIRST).is_ok());
    assert!(pins.pin(&first, SECOND).is_err());
    // Unpinning an unknown subject is harmless.
    assert!(pins.unpin(&subject("unknown")).is_ok());
}

#[test]
fn one_owner_releasing_a_subject_keeps_the_stream_for_the_others() {
    let mut pins = StreamPins::default();
    // Zero retention: a release that really freed the subject would free it at once.
    pins.ttl = Duration::ZERO;
    let user = subject("shared");
    assert!(pins.pin_for(&user, FIRST, Owner::Approval).is_ok());
    assert!(pins.pin_for(&user, FIRST, Owner::Sandbox).is_ok());
    assert!(pins.unpin_for(&user, Owner::Sandbox).is_ok());
    // The approval scope still holds the stream, so a second stream stays refused.
    assert!(matches!(
        pins.pin_for(&user, SECOND, Owner::Sandbox),
        Err(Error::Conflict)
    ));
    assert!(pins.unpin_for(&user, Owner::Approval).is_ok());
    // Only the last holder's release starts the retention clock.
    assert!(pins.pin_for(&user, SECOND, Owner::Sandbox).is_ok());
}
