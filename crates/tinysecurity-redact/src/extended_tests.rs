use super::*;
use tinysecurity_bus::RedactMode;

fn base(secrets: &[&str]) -> Result<Redactor> {
    Redactor::new(&RedactorConfig {
        secrets: secrets.iter().map(|s| Secret((*s).into())).collect(),
    })
}

fn request(text: &str, mode: RedactMode, secrets: &[&str]) -> RedactWithRequest {
    RedactWithRequest {
        text: text.into(),
        mode,
        secrets: secrets.iter().map(|s| Secret((*s).into())).collect(),
    }
}

#[test]
fn a_call_literal_is_removed_in_every_text_mode() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    for mode in [RedactMode::Text, RedactMode::CredentialsOnly] {
        let out = cache.redact(
            &registry,
            &request("key=tenant-key-12345 ok", mode, &["tenant-key-12345"]),
        )?;
        assert!(!out.text.contains("tenant-key-12345"), "{}", out.text);
        assert!(out.changed);
    }
    Ok(())
}

#[test]
fn a_call_literal_is_removed_in_url_encoded_and_base64_forms() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let secret = "Composio-Key_123";
    let encoded = "Composio%2DKey%5F123";
    let base64 = "Q29tcG9zaW8tS2V5XzEyMw==";
    let url_base64 = "Q29tcG9zaW8tS2V5XzEyMw";
    let output = cache.redact(
        &base(&[])?,
        &request(
            &format!("url={encoded} basic={base64} urlsafe={url_base64}"),
            RedactMode::Text,
            &[secret],
        ),
    )?;
    for form in [encoded, base64, url_base64] {
        assert!(!output.text.contains(form), "{}", output.text);
    }
    Ok(())
}

#[test]
fn a_call_literal_is_removed_from_structured_arguments_too() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let out = cache.redact(
        &base(&[])?,
        &request(
            r#"{"note":"see tenant-key-12345 here"}"#,
            RedactMode::StructuredLogArguments,
            &["tenant-key-12345"],
        ),
    )?;
    assert!(!out.text.contains("tenant-key-12345"), "{}", out.text);
    Ok(())
}

#[test]
fn without_literals_the_answer_is_the_plain_registry_answer() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    let out = cache.redact(
        &registry,
        &request("hello world", RedactMode::CredentialsOnly, &[]),
    )?;
    assert_eq!(out.text, "hello world");
    assert!(!out.changed);
    assert!(
        cache.is_empty(),
        "no extended registry is built for no literals"
    );
    Ok(())
}

#[test]
fn call_literals_supplement_the_initialization_registry() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&["init-secret-9999"])?;
    let out = cache.redact(
        &registry,
        &request(
            "init-secret-9999 and call-secret-8888",
            RedactMode::CredentialsOnly,
            &["call-secret-8888"],
        ),
    )?;
    assert!(!out.text.contains("init-secret-9999"));
    assert!(!out.text.contains("call-secret-8888"));
    Ok(())
}

#[test]
fn one_calls_literal_does_not_leak_into_the_next_call() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    let first = cache.redact(
        &registry,
        &request(
            "a tenant-a-key-1111",
            RedactMode::CredentialsOnly,
            &["tenant-a-key-1111"],
        ),
    )?;
    assert!(!first.text.contains("tenant-a-key-1111"));
    let second = cache.redact(
        &registry,
        &request(
            "b tenant-a-key-1111",
            RedactMode::CredentialsOnly,
            &["tenant-b-key-2222"],
        ),
    )?;
    assert!(
        second.text.contains("tenant-a-key-1111"),
        "tenant A's literal must not apply to B's call"
    );
    Ok(())
}

#[test]
fn the_same_literals_reuse_one_cached_registry() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    for _ in 0..3 {
        cache.redact(
            &registry,
            &request("x", RedactMode::Text, &["reused-key-1234"]),
        )?;
    }
    assert_eq!(cache.len(), 1);
    Ok(())
}

#[test]
fn a_different_initialization_registry_never_shares_a_cached_entry() -> Result<()> {
    let cache = ExtendedRedactors::new();
    cache.redact(
        &base(&[])?,
        &request("x", RedactMode::Text, &["shared-key-1234"]),
    )?;
    cache.redact(
        &base(&["init-secret-9999"])?,
        &request("x", RedactMode::Text, &["shared-key-1234"]),
    )?;
    assert_eq!(cache.len(), 2);
    Ok(())
}

#[test]
fn the_cache_is_bounded_and_an_evicted_registry_is_rebuilt() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    for i in 0..(EXTENDED_CAPACITY + 8) {
        let key = format!("bounded-key-{i:04}");
        let out = cache.redact(
            &registry,
            &request(&format!("v {key}"), RedactMode::Text, &[key.as_str()]),
        )?;
        assert!(!out.text.contains(&key));
    }
    assert_eq!(cache.len(), EXTENDED_CAPACITY);
    let first = "bounded-key-0000";
    let out = cache.redact(
        &registry,
        &request(&format!("v {first}"), RedactMode::Text, &[first]),
    )?;
    assert!(
        !out.text.contains(first),
        "an evicted literal is rebuilt, not skipped"
    );
    Ok(())
}

#[test]
fn out_of_bounds_literals_are_a_bad_request_and_nothing_is_cached() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    for secrets in [
        vec!["abc".to_string()],
        vec!["x".repeat(4097)],
        (0..129)
            .map(|i| format!("many-keys-{i:04}"))
            .collect::<Vec<_>>(),
        vec!["[REDACTED]".to_string()],
    ] {
        let refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let error = cache
            .redact(&registry, &request("text", RedactMode::Text, &refs))
            .err()
            .ok_or(Error::Faulted)?;
        assert!(matches!(error, Error::InvalidArguments), "{error:?}");
    }
    assert!(cache.is_empty());
    Ok(())
}

#[test]
fn oversized_text_is_still_refused_with_literals() -> Result<()> {
    let cache = ExtendedRedactors::new();
    let registry = base(&[])?;
    let big = "x".repeat(crate::MAX_INPUT + 1);
    assert!(
        cache
            .redact(
                &registry,
                &request(&big, RedactMode::Text, &["some-key-1234"])
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn a_poisoned_cache_faults_instead_of_answering() -> Result<()> {
    let cache = std::sync::Arc::new(ExtendedRedactors::new());
    let held = std::sync::Arc::clone(&cache);
    let _ = std::thread::spawn(move || {
        let _guard = held.entries.lock();
        std::panic::resume_unwind(Box::new("poison the cache"));
    })
    .join();
    let error = cache
        .redact(
            &base(&[])?,
            &request("x", RedactMode::Text, &["poisoned-key-1"]),
        )
        .err()
        .ok_or(Error::Faulted)?;
    assert!(matches!(error, Error::Faulted), "{error:?}");
    assert_eq!(cache.len(), 0);
    Ok(())
}
