//! Fixed linear-time patterns and validated identifiers; registry contents stay private.
use crate::{MARKER, output_bounded};
use base64::Engine as _;
use regex::Regex;
use tinysecurity_bus::{Error, RedactorConfig, Result};
pub(crate) struct Patterns {
    literal: Option<Regex>,
    rules: Vec<(Regex, Validator)>,
    pem: Regex,
    assignment: Regex,
    gated_assignment: Regex,
    cookie: Regex,
    home: Regex,
    endpoint: Regex,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Validator {
    Always,
    Card,
    Iban,
    NationalId,
    Ip,
    Phone,
}
impl Patterns {
    pub(crate) fn new(config: &RedactorConfig) -> Result<Self> {
        let raw: Vec<_> = config
            .secrets
            .iter()
            .map(|secret| secret.0.as_str())
            .collect();
        if raw.len() > 128
            || raw.iter().map(|s| s.len()).sum::<usize>() > 16_384
            || raw.iter().any(|s| {
                !(4..=4096).contains(&s.len())
                    || [
                        MARKER,
                        "<HOME>",
                        "<redacted: string",
                        "<redacted: array",
                        "<redacted: object",
                        "<redacted: number>",
                        "<redacted: bool>",
                    ]
                    .iter()
                    .any(|marker| marker.contains(*s) || s.contains(marker))
                    || marker_collision(s)
            })
        {
            return Err(Error::InvalidConfig);
        }
        let mut secrets: Vec<String> = raw.into_iter().flat_map(encoded_forms).collect();
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        let literal = if secrets.is_empty() {
            None
        } else {
            Some(compile(
                &secrets
                    .iter()
                    .map(|s| regex::escape(s))
                    .collect::<Vec<_>>()
                    .join("|"),
            )?)
        };
        let definitions = [
            (
                r"\b(?:sk-(?:ant-|admin-|proj-|org-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[abeprs]-[A-Za-z0-9-]{10,}|[spr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20,})\b",
                Validator::Always,
            ),
            (
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                Validator::Always,
            ),
            (
                r"(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)",
                Validator::Always,
            ),
            (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                Validator::Always,
            ),
            (
                r"\b[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}\b",
                Validator::NationalId,
            ),
            (r"\b[0-9](?:[ -]?[0-9]){12,18}\b", Validator::Card),
            (r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b", Validator::Iban),
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", Validator::Ip),
            (
                r"(?:\+1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}\b|\+[0-9](?:[0-9 -]{6,16}[0-9])",
                Validator::Phone,
            ),
            (
                r"(?i)\b[0-9]{1,6}\s+[A-Za-z0-9.' -]{2,40}?\b(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|ter|circle|cir|highway|hwy)\b",
                Validator::Always,
            ),
        ];
        Ok(Self {
            literal,
            rules: definitions
                .into_iter()
                .map(|(p, v)| compile(p).map(|r| (r, v)))
                .collect::<Result<_>>()?,
            pem: compile(
                r"(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)",
            )?,
            assignment: compile(
                r#"(?i)\b(authorization["']?[ \t]*[=:][ \t]*(?:(?:bearer|basic|digest|token)[ \t]+)?|bearer[ \t]+|(?:x-api-key|api[_-]?(?:key|secret)|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|client[_-]?secret|proxy-authorization|passwd|password|secret|token)["']?[ \t]*[=:][ \t]*)(?:\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\}\]]+)"#,
            )?,
            gated_assignment: compile(
                r#"(?i)\b(authorization["']?[ \t]*[=:][ \t]*(?:(?:bearer|basic|digest|token)[ \t]+)?|bearer[ \t]+|(?:x-api-key|api[_-]?(?:key|secret)|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|client[_-]?secret|proxy-authorization|passwd|password|secret|token)["']?[ \t]*[=:][ \t]*)(\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\}\]]+)"#,
            )?,
            // A Cookie header is a `;`-separated list; the whole line is the credential.
            cookie: compile(
                r#"(?i)\b((?:set-)?cookie["']?[ \t]*[=:][ \t]*)(?:\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]+)"#,
            )?,
            home: compile(r#"(?i)(?:/(?:home|users)/|[a-z]:[\\/]+users[\\/]+)[^\\/\s"'<>]+"#)?,
            endpoint: compile(r#"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+"#)?,
        })
    }
    pub(crate) fn literal(&self, text: &str) -> String {
        self.literal.as_ref().map_or_else(
            || text.into(),
            |r| r.replace_all(text, regex::NoExpand(MARKER)).into_owned(),
        )
    }
    pub(crate) fn text(&self, text: &str) -> Result<String> {
        // A private key block goes first: an assignment such as `Authorization: Bearer
        // -----BEGIN ...` would otherwise consume only the first word of the PEM.
        let mut out = self.literal(text);
        out = self.pem.replace_all(&out, MARKER).into_owned();
        out = self
            .assignment
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                format!("{}{MARKER}", &caps[1])
            })
            .into_owned();
        out = self
            .cookie
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                format!("{}{MARKER}", &caps[1])
            })
            .into_owned();
        output_bounded(&out)?;
        out = self
            .endpoint
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                url::Url::parse(&caps[0])
                    .ok()
                    .and_then(|mut u| {
                        u.host_str()?;
                        u.set_username("").ok()?;
                        u.set_password(None).ok()?;
                        u.set_query(None);
                        u.set_fragment(None);
                        let normalized = u.to_string().trim_end_matches('/').to_owned();
                        // URL normalization removes userinfo and folds authority case.
                        // Check retained parts before emitting a parseable endpoint.
                        Some(if self.retained_endpoint_is_sensitive(&normalized) {
                            MARKER.into()
                        } else {
                            normalized
                        })
                    })
                    .unwrap_or_else(|| MARKER.into())
            })
            .into_owned();
        out = self.home.replace_all(&out, "<HOME>").into_owned();
        for (regex, validator) in &self.rules {
            let source = out;
            out = regex
                .replace_all(&source, |caps: &regex::Captures<'_>| {
                    let Some(matched) = caps.get(0) else {
                        return String::new();
                    };
                    let start = matched.start().saturating_sub(64);
                    let end = (matched.end() + 64).min(source.len());
                    let mut start = start;
                    let mut end = end;
                    while !source.is_char_boundary(start) {
                        start -= 1;
                    }
                    while !source.is_char_boundary(end) {
                        end += 1;
                    }
                    let context = &source[start..end];
                    if validator_valid(*validator, &caps[0], context) {
                        MARKER.into()
                    } else {
                        caps[0].to_string()
                    }
                })
                .into_owned();
            output_bounded(&out)?;
        }
        // Transformations can create an exact literal that was absent initially.
        // One final pass is bounded and markers cannot contain registered literals.
        let out = self.literal(&out);
        output_bounded(&out)?;
        Ok(out)
    }
    /// Credential-only sanitation for free-form tool output: the exact registry,
    /// provider token shapes, JWTs, private keys, cookie headers and labelled
    /// values that look like a credential. Contact data, cards, addresses,
    /// home paths and URLs are left alone, and a labelled value that reads as
    /// ordinary source code (`token = get_token()`, `token: string`) is kept.
    pub(crate) fn credentials(&self, text: &str) -> Result<String> {
        let mut out = self.literal(text);
        out = self.pem.replace_all(&out, MARKER).into_owned();
        for (regex, _) in self.rules.iter().take(2) {
            out = regex.replace_all(&out, MARKER).into_owned();
        }
        let source = out.clone();
        out = self
            .gated_assignment
            .replace_all(&source, |caps: &regex::Captures<'_>| {
                let start = caps.get(0).map_or(0, |m| m.start());
                let whole = caps.get(0).map_or(0, |m| m.end());
                if secret_like(&caps[1], &caps[2], &source[..start], &source[whole..]) {
                    format!("{}{MARKER}", &caps[1])
                } else {
                    caps[0].to_string()
                }
            })
            .into_owned();
        out = self
            .cookie
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                format!("{}{MARKER}", &caps[1])
            })
            .into_owned();
        output_bounded(&out)?;
        let out = self.literal(&out);
        output_bounded(&out)?;
        Ok(out)
    }
    pub(crate) fn retained_endpoint_is_sensitive(&self, text: &str) -> bool {
        self.literal.as_ref().is_some_and(|r| r.is_match(text))
            || self.assignment.is_match(text)
            || self.cookie.is_match(text)
            || self
                .rules
                .iter()
                .any(|(rule, validator)| rule.find_iter(text).any(|m| validator.valid(m.as_str())))
    }
}
fn encoded_forms(secret: &str) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let mut percent = String::with_capacity(secret.len() * 3);
    let mut percent_lower = String::with_capacity(secret.len() * 3);
    let mut form = String::with_capacity(secret.len() * 3);
    for byte in secret.bytes() {
        if byte.is_ascii_alphanumeric() {
            percent.push(char::from(byte));
            percent_lower.push(char::from(byte));
            form.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(percent, "%{byte:02X}");
            let _ = write!(percent_lower, "%{byte:02x}");
            if byte == b' ' {
                form.push('+');
            } else {
                let _ = write!(form, "%{byte:02X}");
            }
        }
    }
    vec![
        secret.into(),
        percent.clone(),
        percent_lower,
        form,
        STANDARD.encode(secret),
        STANDARD_NO_PAD.encode(secret),
        URL_SAFE.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
    ]
}
/// Decide whether a labelled value is a credential rather than source code.
fn secret_like(label: &str, raw: &str, prefix: &str, rest: &str) -> bool {
    let value = raw.trim_matches(|c| c == '"' || c == '\'');
    if value == MARKER {
        return false;
    }
    if [
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "AKIA",
        "ASIA",
        "eyJ",
        "xox",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
    {
        return true;
    }
    let scheme = label.to_ascii_lowercase();
    let scheme = scheme.trim_end();
    if scheme.starts_with("bearer") || scheme.ends_with("bearer") || scheme.ends_with("basic") {
        return value.len() >= 8;
    }
    if is_declared_source_expression(raw, prefix) {
        return false;
    }
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    if value
        .find('<')
        .is_some_and(|open| value[open..].contains('>'))
    {
        return false;
    }
    if value.starts_with('=') {
        return false;
    }
    let mut after = rest.chars();
    match after.next() {
        Some('(' | '[') => return false,
        Some('.') if after.next().is_some_and(|c| c.is_alphabetic() || c == '_') => return false,
        _ => {}
    }
    if value.contains(['(', ')', '{', '[']) {
        return false;
    }
    // A digitless identifier or dotted member path reads a value in code. A
    // credential of that shape is caught by the exact registry instead.
    let unquoted = raw.len() == value.len();
    if unquoted
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '.'))
    {
        return false;
    }
    value.parse::<f64>().is_err()
}

fn is_declared_source_expression(raw: &str, prefix: &str) -> bool {
    let value = raw.trim();
    if value.is_empty()
        || !value
            .chars()
            .any(|ch| ch.is_ascii_alphabetic() || ch == '_' || ch == '$')
        || !value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '_' | '$'
                        | '.'
                        | '+'
                        | '-'
                        | '*'
                        | '/'
                        | '%'
                        | '('
                        | ')'
                        | '?'
                        | ':'
                        | '|'
                        | '&'
                        | '!'
                        | '<'
                        | '>'
                        | '='
                        | '~'
                        | '^'
                )
        })
    {
        return false;
    }

    let prefix = prefix.trim_end();
    ["let mut", "let", "const", "var"].iter().any(|keyword| {
        prefix.strip_suffix(keyword).is_some_and(|before| {
            before
                .chars()
                .next_back()
                .is_none_or(|ch| ch.is_whitespace() || matches!(ch, ';' | '{' | '('))
        })
    })
}
fn marker_collision(secret: &str) -> bool {
    let skeleton: String = secret.chars().filter(|c| !c.is_ascii_digit()).collect();
    if skeleton.is_empty() {
        return secret.len() <= 6;
    }
    [
        "<redacted: string ( chars)>",
        "<redacted: array ( items)>",
        "<redacted: object ( keys)>",
    ]
    .iter()
    .any(|marker| marker.contains(&skeleton))
}
fn compile(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|_| Error::InvalidConfig)
}
impl Validator {
    fn valid(self, text: &str) -> bool {
        match self {
            Self::Always => true,
            Self::Ip => text.parse::<std::net::Ipv4Addr>().is_ok(),
            Self::NationalId => {
                let digits: String = text.chars().filter(char::is_ascii_digit).collect();
                !matches!(&digits[..3], "000" | "666")
                    && !digits.starts_with('9')
                    && &digits[3..5] != "00"
                    && &digits[5..] != "0000"
            }
            Self::Phone => (7..=15).contains(&text.bytes().filter(u8::is_ascii_digit).count()),
            Self::Card => {
                let digits: Vec<_> = text
                    .bytes()
                    .filter(u8::is_ascii_digit)
                    .map(|b| b - b'0')
                    .collect();
                (13..=19).contains(&digits.len())
                    && (matches!(digits.first(), Some(3..=7))
                        || (digits.first() == Some(&2)
                            && digits.get(1).is_some_and(|digit| (2..=7).contains(digit))))
                    && digits
                        .iter()
                        .rev()
                        .enumerate()
                        .map(|(i, &d)| {
                            let n = u32::from(d) * if i % 2 == 1 { 2 } else { 1 };
                            if n > 9 { n - 9 } else { n }
                        })
                        .sum::<u32>()
                        % 10
                        == 0
            }
            Self::Iban => {
                let mut remainder = 0u32;
                for b in text.bytes().skip(4).chain(text.bytes().take(4)) {
                    let n = if b.is_ascii_digit() {
                        u32::from(b - b'0')
                    } else {
                        u32::from(b - b'A') + 10
                    };
                    remainder = (remainder * if n < 10 { 10 } else { 100 } + n) % 97;
                }
                remainder == 1
            }
        }
    }
}
fn validator_valid(validator: Validator, text: &str, context: &str) -> bool {
    if validator != Validator::Card {
        return validator.valid(text);
    }
    if validator.valid(text) && card_issuer_and_length(text) {
        return true;
    }
    let lowered = context.to_ascii_lowercase();
    [
        "card",
        "credit",
        "debit",
        "visa",
        "mastercard",
        "amex",
        "discover",
    ]
    .iter()
    .any(|keyword| lowered.contains(keyword))
        && luhn_checksum(text)
}
fn luhn_checksum(text: &str) -> bool {
    let digits: Vec<_> = text
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    (13..=19).contains(&digits.len())
        && digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                let n = u32::from(d) * if i % 2 == 1 { 2 } else { 1 };
                if n > 9 { n - 9 } else { n }
            })
            .sum::<u32>()
            % 10
            == 0
}
fn card_issuer_and_length(text: &str) -> bool {
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    let len = digits.len();
    let starts = |prefix: &str| digits.starts_with(prefix);
    let visa = starts("4") && matches!(len, 13 | 16 | 19);
    let mastercard = ((51..=55).any(|prefix| digits.starts_with(&prefix.to_string()))
        || (2221..=2720).any(|prefix| digits.starts_with(&prefix.to_string())))
        && len == 16;
    let amex = (starts("34") || starts("37")) && len == 15;
    let discover = (starts("6011") || starts("65") || starts("644") || starts("645")) && len == 16;
    visa || mastercard || amex || discover
}
#[cfg(test)]
#[path = "patterns_tests.rs"]
mod tests;
