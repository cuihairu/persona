//! Logging utilities with automatic secrets redaction.
//!
//! This module provides a thin wrapper around `tracing_subscriber` that installs a formatter
//! which scrubs sensitive values (passwords, tokens, keys, etc.) before they are written to logs.
//! It is reused by every Persona binary so that CLI, agent, and server logs follow the same policy.

use chrono::{SecondsFormat, Utc};
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::fmt::{self, Write};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent};
use tracing_subscriber::registry::LookupSpan;

const DEFAULT_SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "passphrase",
    "secret",
    "token",
    "secret_key",
    "secret-key",
    "private_key",
    "private-key",
    "ssh_key",
    "ssh-key",
    "api_key",
    "api-key",
    "access_token",
    "refresh_token",
    "session_token",
    "master_password",
    "vault_password",
    "mnemonic",
    "seed",
    "recovery_phrase",
    "totp_secret",
    "otp_secret",
];

const CODE_FIELDS: &[&str] = &[
    "otp",
    "totp",
    "code",
    "passcode",
    "verification_code",
    "auth_code",
];

const AUTH_HEADERS: &[&str] = &["authorization", "auth_header", "auth-header"];

/// Builder for installing a redacted tracing subscriber.
pub struct RedactedLoggerBuilder {
    level: tracing::Level,
    include_timestamp: bool,
    include_target: bool,
    policy: RedactionPolicy,
    writer: Option<WriterFactory>,
}

/// Factory producing the sink the subscriber writes formatted lines to.
type WriterFactory = Box<dyn Fn() -> Box<dyn std::io::Write + Send> + Send + Sync>;

impl RedactedLoggerBuilder {
    /// Start a new builder at the desired log level.
    pub fn new(level: tracing::Level) -> Self {
        Self {
            level,
            include_timestamp: true,
            include_target: false,
            policy: RedactionPolicy::default(),
            writer: None,
        }
    }

    /// Toggle whether timestamps should be included in log lines (default: true).
    pub fn include_timestamp(mut self, include: bool) -> Self {
        self.include_timestamp = include;
        self
    }

    /// Toggle whether the tracing target/module path is rendered (default: false).
    pub fn include_target(mut self, include: bool) -> Self {
        self.include_target = include;
        self
    }

    /// Override the default redaction policy.
    pub fn policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Route log output to a custom writer factory instead of stdout.
    ///
    /// The factory is called once per formatted event and must return a writer
    /// safe to write a single line to; sharing a `Mutex<File>` behind the
    /// factory is the intended pattern for file-backed logging.
    pub fn with_writer(
        mut self,
        make: impl Fn() -> Box<dyn std::io::Write + Send> + Send + Sync + 'static,
    ) -> Self {
        self.writer = Some(Box::new(make));
        self
    }

    /// Finish configuring and install the subscriber globally.
    pub fn init(self) -> Result<(), tracing_subscriber::util::TryInitError> {
        let formatter =
            RedactingFormatter::new(self.policy, self.include_timestamp, self.include_target);

        let subscriber = tracing_subscriber::fmt()
            .with_max_level(self.level)
            .with_target(self.include_target)
            .event_format(formatter);

        match self.writer {
            Some(factory) => {
                tracing_subscriber::util::SubscriberInitExt::try_init(
                    subscriber.with_writer(factory),
                )?;
            }
            None => tracing_subscriber::util::SubscriberInitExt::try_init(subscriber)?,
        };

        Ok(())
    }
}

/// Convenience helper for common initialization with default policy.
pub fn init_redacted_tracing(
    level: tracing::Level,
) -> Result<(), tracing_subscriber::util::TryInitError> {
    RedactedLoggerBuilder::new(level).init()
}

/// Redaction policy with compiled rules.
#[derive(Clone)]
pub struct RedactionPolicy {
    mask: String,
    rules: Vec<RedactionRule>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::new("[REDACTED]")
    }
}

impl RedactionPolicy {
    /// Create a policy with a custom mask token.
    pub fn new(mask: impl Into<String>) -> Self {
        let mask = mask.into();
        let rules = build_default_rules();
        Self { mask, rules }
    }

    /// Apply redaction to the provided string, returning a borrowed value when unchanged.
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str> {
        self.rules.iter().fold(Cow::Borrowed(input), |acc, rule| {
            rule.apply(acc, &self.mask)
        })
    }
}

#[derive(Clone)]
struct RedactionRule {
    pattern: Regex,
    kind: RedactionRuleKind,
}

#[derive(Clone, Copy)]
enum RedactionRuleKind {
    KeyValue,
    JsonValue,
    AuthorizationHeader,
    BareSecret,
    NumericCode,
}

impl RedactionRule {
    fn apply<'a>(&self, text: Cow<'a, str>, mask: &str) -> Cow<'a, str> {
        if !self.pattern.is_match(text.as_ref()) {
            return text;
        }

        let replaced = match self.kind {
            RedactionRuleKind::KeyValue => {
                self.pattern.replace_all(text.as_ref(), |caps: &Captures| {
                    format!("{}{}{}", &caps["key"], &caps["sep"], mask)
                })
            }
            RedactionRuleKind::JsonValue => {
                self.pattern.replace_all(text.as_ref(), |caps: &Captures| {
                    format!("{}{}{}", &caps["prefix"], mask, &caps["suffix"])
                })
            }
            RedactionRuleKind::AuthorizationHeader => {
                self.pattern.replace_all(text.as_ref(), |caps: &Captures| {
                    let prefix = caps.name("prefix").map(|m| m.as_str()).unwrap_or("");
                    let scheme = caps.name("scheme").map(|m| m.as_str()).unwrap_or("");
                    format!("{}{}{}", prefix, scheme, mask)
                })
            }
            RedactionRuleKind::BareSecret => {
                self.pattern.replace_all(text.as_ref(), |caps: &Captures| {
                    let mid = caps.name("mid").map(|m| m.as_str()).unwrap_or(" ");
                    format!("{}{}{}", &caps["key"], mid, mask)
                })
            }
            RedactionRuleKind::NumericCode => {
                self.pattern.replace_all(text.as_ref(), |caps: &Captures| {
                    let sep = caps.name("sep").map(|m| m.as_str()).unwrap_or(" ");
                    format!("{}{}{}", &caps["key"], sep, mask)
                })
            }
        };

        Cow::Owned(replaced.into_owned())
    }
}

fn build_default_rules() -> Vec<RedactionRule> {
    let sensitive_pattern = build_keyword_pattern(DEFAULT_SENSITIVE_FIELDS);
    let code_pattern = build_keyword_pattern(CODE_FIELDS);
    let header_pattern = build_keyword_pattern(AUTH_HEADERS);

    vec![
        RedactionRule {
            pattern: Regex::new(&format!(
                r#"(?i)(?P<key>\b(?:{sensitive})\b)(?P<sep>\s*[:=]\s*)(?P<value>"[^"]+"|'[^']+'|[^\s,;]+)"#,
                sensitive = sensitive_pattern
            ))
            .expect("invalid key-value regex"),
            kind: RedactionRuleKind::KeyValue,
        },
        RedactionRule {
            pattern: Regex::new(&format!(
                r#"(?i)(?P<prefix>"(?:{sensitive})"\s*:\s*")(?P<value>[^"]*)(?P<suffix>")"#,
                sensitive = sensitive_pattern
            ))
            .expect("invalid JSON regex"),
            kind: RedactionRuleKind::JsonValue,
        },
        RedactionRule {
            pattern: Regex::new(&format!(
                r#"(?i)(?P<prefix>\b(?:{headers})\b\s*[:=]\s*)(?P<scheme>(?:bearer|basic|token)\s+)?(?P<value>[A-Za-z0-9\.\-_+/=]{{6,}})"#,
                headers = header_pattern
            ))
            .expect("invalid Authorization regex"),
            kind: RedactionRuleKind::AuthorizationHeader,
        },
        RedactionRule {
            pattern: Regex::new(&format!(
                r#"(?i)(?P<key>\b(?:{sensitive})\b)(?P<mid>\s+(?:is\s+|was\s+|value\s+|code\s+|token\s+|set\s+to\s+)?)(?P<value>[A-Za-z0-9+/=_-]{{6,}})"#,
                sensitive = sensitive_pattern
            ))
            .expect("invalid bare secret regex"),
            kind: RedactionRuleKind::BareSecret,
        },
        RedactionRule {
            pattern: Regex::new(&format!(
                r#"(?i)(?P<key>\b(?:{codes})\b)(?P<sep>\s*(?:[:=]|is|was)?\s*)(?P<value>\d{{4,10}})"#,
                codes = code_pattern
            ))
            .expect("invalid numeric code regex"),
            kind: RedactionRuleKind::NumericCode,
        },
    ]
}

fn build_keyword_pattern(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| regex::escape(value))
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Default)]
struct EventFieldCollector {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl EventFieldCollector {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }
}

impl Visit for EventFieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{:?}", value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_value(field, value.to_string());
    }
}

#[derive(Clone)]
struct RedactingFormatter {
    policy: RedactionPolicy,
    include_timestamp: bool,
    include_target: bool,
}

impl RedactingFormatter {
    fn new(policy: RedactionPolicy, include_timestamp: bool, include_target: bool) -> Self {
        Self {
            policy,
            include_timestamp,
            include_target,
        }
    }
}

impl<S, N> FormatEvent<S, N> for RedactingFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut line = String::new();

        if self.include_timestamp {
            let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            write!(line, "{} ", now)?;
        }

        write!(line, "{:<5}", event.metadata().level())?;

        if self.include_target {
            write!(line, " {} ", event.metadata().target())?;
        } else {
            line.push(' ');
        }

        let mut collector = EventFieldCollector::default();
        event.record(&mut collector);

        if collector.message.is_some() || !collector.fields.is_empty() {
            line.push_str("- ");
        }

        if let Some(message) = collector.message.as_ref() {
            line.push_str(message);
        }

        if !collector.fields.is_empty() {
            if collector.message.is_some() {
                line.push(' ');
            }

            let formatted = collector
                .fields
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(" ");
            line.push_str(&formatted);
        }

        let sanitized = self.policy.redact(&line);
        writer.write_str(&sanitized)?;
        writer.write_char('\n')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_key_value_secret() {
        let policy = RedactionPolicy::default();
        let msg = "password=supersecret";
        let redacted = policy.redact(msg);
        assert_eq!(redacted, "password=[REDACTED]");
    }

    #[test]
    fn redacts_json_secret() {
        let policy = RedactionPolicy::default();
        let msg = r#"{"api_key":"abcd1234"}"#;
        let redacted = policy.redact(msg);
        assert_eq!(redacted, r#"{"api_key":"[REDACTED]"}"#);
    }

    #[test]
    fn redacts_authorization_header() {
        let policy = RedactionPolicy::default();
        let msg = "Authorization: Bearer abcdef012345";
        let redacted = policy.redact(msg);
        assert_eq!(redacted, "Authorization: Bearer [REDACTED]");
    }

    #[test]
    fn redacts_inline_secret() {
        let policy = RedactionPolicy::default();
        let msg = "Using token abcdef0123456789 for sync";
        let redacted = policy.redact(msg);
        assert_eq!(redacted, "Using token [REDACTED] for sync");
    }

    #[test]
    fn redacts_numeric_codes() {
        let policy = RedactionPolicy::default();
        let msg = "OTP 123456";
        let redacted = policy.redact(msg);
        assert_eq!(redacted, "OTP [REDACTED]");
    }

    #[test]
    fn redacts_quoted_key_values_and_multiple_occurrences() {
        let policy = RedactionPolicy::default();

        // Single- and double-quoted values are both covered by the KeyValue rule.
        assert_eq!(
            policy.redact(r#"secret="hunter2" passphrase='other'"#),
            r#"secret=[REDACTED] passphrase=[REDACTED]"#
        );

        // Case-insensitive keywords, `=` without spaces, several matches per line.
        assert_eq!(
            policy.redact("PASSWORD=hunter2 api-key: abcd1234; token,whatever"),
            "PASSWORD=[REDACTED] api-key: [REDACTED]; token,whatever"
        );
    }

    #[test]
    fn redacts_code_keyword_variants() {
        let policy = RedactionPolicy::default();

        assert_eq!(policy.redact("totp=987654"), "totp=[REDACTED]");
        assert_eq!(
            policy.redact("verification code is 654321"),
            "verification code is [REDACTED]"
        );
        // Short digit runs (fewer than 4) are not treated as codes.
        assert_eq!(policy.redact("code 42"), "code 42");
    }

    #[test]
    fn redacts_bare_secret_and_header_without_scheme() {
        let policy = RedactionPolicy::default();

        // "is" connector between keyword and value (kept by the mid capture).
        assert_eq!(
            policy.redact("the mnemonic is abcdef123456"),
            "the mnemonic is [REDACTED]"
        );

        // Authorization header without a bearer/basic scheme.
        assert_eq!(
            policy.redact("auth_header: Zm9vYmFyYmF6"),
            "auth_header: [REDACTED]"
        );
    }

    #[test]
    fn custom_mask_is_used_verbatim() {
        let policy = RedactionPolicy::new("<hidden>");
        assert_eq!(policy.redact("password=hunter2"), "password=<hidden>");
    }

    #[test]
    fn redact_returns_borrowed_value_when_nothing_matches() {
        let policy = RedactionPolicy::default();
        let clean = "nothing sensitive in here";
        match policy.redact(clean) {
            Cow::Borrowed(s) => assert_eq!(s, clean),
            Cow::Owned(s) => panic!("expected a borrowed cow, got owned: {s}"),
        }
    }

    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriter(self.0.clone())
        }
    }

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn builder_chain_toggles_configuration_fields() {
        let builder = RedactedLoggerBuilder::new(tracing::Level::DEBUG)
            .include_timestamp(false)
            .include_target(true)
            .policy(RedactionPolicy::new("[X]".to_string()));

        assert_eq!(builder.level, tracing::Level::DEBUG);
        assert!(!builder.include_timestamp);
        assert!(builder.include_target);
        assert_eq!(builder.policy.mask, "[X]");
        assert!(builder.writer.is_none(), "stdout is the default sink");

        // Default builder state.
        let default = RedactedLoggerBuilder::new(tracing::Level::INFO);
        assert!(default.include_timestamp);
        assert!(!default.include_target);
    }

    #[test]
    fn with_writer_stores_a_working_factory() {
        let sink = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        let builder = RedactedLoggerBuilder::new(tracing::Level::INFO).with_writer({
            let sink = sink.clone();
            move || Box::new(SharedWriter(sink.0.clone()))
        });

        let factory = builder.writer.as_ref().expect("writer factory stored");
        let mut writer = factory();
        writer.write_all(b"a line\n").unwrap();
        writer.write_all(b"password=hunter2\n").unwrap();

        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "a line\npassword=hunter2\n");
    }

    #[test]
    fn formatter_renders_levels_targets_and_all_field_types() {
        let formatter = RedactingFormatter::new(RedactionPolicy::default(), false, true);
        let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .event_format(formatter)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(buf.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "logging::test", "plain message");
            let secret = "hunter2";
            let count: i64 = -3;
            let big: u64 = 7;
            let flag: bool = true;
            tracing::warn!(password = secret, "secret field");
            tracing::info!(count, big, flag, "typed fields");
            let io_err = std::io::Error::other("disk exploded");
            let err_ref: &(dyn std::error::Error + 'static) = &io_err;
            tracing::error!(error = err_ref, "with error");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("INFO "), "level rendered: {out}");
        assert!(out.contains("logging::test"), "target rendered: {out}");
        assert!(out.contains("plain message"));
        assert!(
            out.contains("password=[REDACTED]"),
            "secret field redacted: {out}"
        );
        assert!(out.contains("count=-3"));
        assert!(out.contains("big=7"));
        assert!(out.contains("flag=true"));
        assert!(out.contains("error=disk exploded"), "error recorded: {out}");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn formatter_can_omit_target_and_redacts_message() {
        let formatter = RedactingFormatter::new(RedactionPolicy::default(), true, false);
        let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .event_format(formatter)
            .with_writer(buf.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "hidden::target", "token abcdef0123456789 leaked");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("hidden::target"), "no target: {out}");
        assert!(out.contains("[REDACTED]"), "message redacted: {out}");
        assert!(out.contains("- "), "timestamp prefix present: {out}");
    }

    #[test]
    fn shared_writer_flush_is_a_noop() {
        let mut writer = SharedWriter(Arc::new(Mutex::new(Vec::new())));
        std::io::Write::flush(&mut writer).unwrap();
        assert!(writer.0.lock().unwrap().is_empty());
    }

    #[test]
    fn init_redacted_tracing_installs_at_most_once() {
        // A process accepts exactly one global subscriber. The first call
        // installs it (or loses a race with a parallel test); a second call
        // must report the conflict cleanly instead of panicking.
        let _first = init_redacted_tracing(tracing::Level::INFO);
        let second = init_redacted_tracing(tracing::Level::INFO);
        assert!(second.is_err(), "a second global init must fail cleanly");
    }
}
