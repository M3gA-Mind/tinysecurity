use super::*;
#[test]
fn invalid_registry_and_bad_pattern_never_echo_payloads() {
    for secret in ["", "abc", "REDACTED", "<HOME>"] {
        assert!(matches!(
            Patterns::new(&RedactorConfig {
                secrets: vec![tinysecurity_bus::Secret(secret.into())]
            }),
            Err(Error::InvalidConfig)
        ));
    }
    assert!(
        Patterns::new(&RedactorConfig {
            secrets: vec![tinysecurity_bus::Secret("abcd".into()); 129]
        })
        .is_err()
    );
    assert!(
        Patterns::new(&RedactorConfig {
            secrets: vec![tinysecurity_bus::Secret("a".repeat(4097))]
        })
        .is_err()
    );
    assert!(
        Patterns::new(&RedactorConfig {
            secrets: vec![tinysecurity_bus::Secret("a".repeat(4096)); 5]
        })
        .is_err()
    );
    assert!(compile("[").is_err());
}
#[test]
fn private_keys_urls_assignments_and_validators_are_selective() -> Result<()> {
    let patterns = Patterns::new(&RedactorConfig::default())?;
    for text in [
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        "https://alice:secret@host/path?q=private#private",
        "token='private'",
        "authorization=private",
        "https://[invalid?q=private",
    ] {
        let out = patterns.text(text)?;
        assert!(!out.contains("secret"));
        assert!(!out.contains("private"));
    }
    assert!(!Validator::Card.valid("0"));
    assert!(!Validator::Card.valid("0000000000000000"));
    assert!(!Validator::NationalId.valid("666-12-1234"));
    assert!(!Validator::NationalId.valid("999-12-1234"));
    assert!(!Validator::NationalId.valid("123-00-1234"));
    assert!(!Validator::NationalId.valid("123-12-0000"));
    assert!(!Validator::Phone.valid("123"));
    assert!(!Validator::Ip.valid("999.1.2.3"));
    assert!(Validator::Iban.valid("DE89370400440532013000"));
    assert!(!Validator::Iban.valid("DE00370400440532013000"));
    Ok(())
}

#[test]
fn card_numbers_need_issuer_or_nearby_context() -> Result<()> {
    let patterns = Patterns::new(&RedactorConfig::default())?;
    let timestamp = "1787178633773";
    assert_eq!(patterns.text(timestamp)?, timestamp);
    let digits = ["7", "123456789012345"].concat();
    let candidate = (0..10)
        .map(|check| format!("{digits}{check}"))
        .find(|value| Validator::Card.valid(value))
        .ok_or(Error::Faulted)?;
    assert_eq!(patterns.text(&candidate)?, candidate);
    assert_eq!(
        patterns.text(&format!("card number {candidate}"))?,
        format!("card number {MARKER}")
    );
    Ok(())
}
#[test]
fn registry_rejects_literals_that_embed_generated_markers() {
    for secret in [
        "[REDACTED]x",
        "prefix<HOME>",
        "prefix<redacted: number>",
        "<redacted: string (123 chars)>suffix",
    ] {
        assert!(
            Patterns::new(&RedactorConfig {
                secrets: vec![tinysecurity_bus::Secret(secret.into())]
            })
            .is_err()
        );
    }
}
