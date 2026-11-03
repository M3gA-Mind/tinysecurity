use super::*;

#[test]
fn legacy_import_events_have_distinct_one_shot_handles() {
    let denied = legacy_import_handle("legacy-import-expired");
    let accepted = legacy_import_handle("legacy-import-event");

    assert_ne!(denied, accepted);
    assert_eq!(
        accepted,
        legacy_import_handle("legacy-import-event"),
        "a retried host event must reuse its consumed handle"
    );
}
