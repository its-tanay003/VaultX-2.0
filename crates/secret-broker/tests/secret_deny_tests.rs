use valutx_secret_broker::redact_text;

#[test]
fn test_empty_secret_does_not_corrupt_text() {
    let text = "regular log message";
    assert_eq!(redact_text(text, &[""]), "regular log message");
}

#[test]
fn test_multi_secret_redaction() {
    let text = "key=AAA and token=BBB";
    assert_eq!(
        redact_text(text, &["AAA", "BBB"]),
        "key=[REDACTED_SECRET] and token=[REDACTED_SECRET]"
    );
}
