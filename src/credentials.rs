use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::scanner::ScanDetection;

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static OPENAI_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-proj-[A-Za-z0-9_-]{20,}").expect("OPENAI_KEY regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static OPENAI_KEY_LEGACY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9]{20,}").expect("OPENAI_KEY_LEGACY regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static OPENAI_KEY_GENERIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9]{10,}").expect("OPENAI_KEY_GENERIC regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("AWS_ACCESS_KEY regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static AWS_SECRET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)aws_secret_access_key\s*[=:]\s*\S+").expect("AWS_SECRET regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static GITHUB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ghp_[A-Za-z0-9]{20,}").expect("GITHUB_PAT regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static GITHUB_OAUTH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gho_[A-Za-z0-9]{20,}").expect("GITHUB_OAUTH regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static GITHUB_PAT_FINE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").expect("GITHUB_PAT_FINE regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static PASSWORD_ASSIGN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)password\s*[=:]\s*["']?\S+"#).expect("PASSWORD_ASSIGN regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static SECRET_ASSIGN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)secret\s*[=:]\s*["']?\S+"#).expect("SECRET_ASSIGN regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static TOKEN_ASSIGN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)token\s*[=:]\s*["']?\S+"#).expect("TOKEN_ASSIGN regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(mongodb|postgres|mysql|redis)://\S+").expect("CONNECTION_STRING regex")
});

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static DOTENV_SECRET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Z_]+_SECRET\s*=\s*\S+").expect("DOTENV_SECRET regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static BASE64_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").expect("BASE64_RE regex"));

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static UNICODE_IGNORE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:[\u2160-\u216f]\w+|ignore[\u2160-\u216f])").expect("UNICODE_IGNORE regex")
});

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static UNICODE_IGNORE_FULL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:[\u2160-\u216f]|\s)*(?:ignore|disregard|override)")
        .expect("UNICODE_IGNORE_FULL regex")
});

static DANGEROUS_DECODED: [&str; 12] = [
    "ignore previous",
    "ignore all",
    "disregard",
    "forget your instructions",
    "system prompt",
    "new instructions",
    "you are now",
    "act as",
    "pretend to be",
    "override",
    "jailbreak",
    "bypass",
];

pub fn scan(text: &str) -> Vec<ScanDetection> {
    let mut detections = Vec::new();

    let patterns: [(&str, &Lazy<Regex>); 13] = [
        ("openai_key", &OPENAI_KEY),
        ("openai_key_legacy", &OPENAI_KEY_LEGACY),
        ("openai_key_generic", &OPENAI_KEY_GENERIC),
        ("aws_access_key", &AWS_ACCESS_KEY),
        ("aws_secret", &AWS_SECRET),
        ("github_pat", &GITHUB_PAT),
        ("github_oauth", &GITHUB_OAUTH),
        ("github_pat_fine", &GITHUB_PAT_FINE),
        ("password_assign", &PASSWORD_ASSIGN),
        ("secret_assign", &SECRET_ASSIGN),
        ("token_assign", &TOKEN_ASSIGN),
        ("connection_string", &CONNECTION_STRING),
        ("dotenv_secret", &DOTENV_SECRET),
    ];

    for (rule_name, pattern) in patterns.iter() {
        if let Some(m) = pattern.find(text) {
            let matched = if m.as_str().len() > 40 {
                format!("{}...", &m.as_str()[..40])
            } else {
                m.as_str().to_string()
            };
            detections.push(ScanDetection {
                scanner: "credentials".to_string(),
                rule: rule_name.to_string(),
                matched,
            });
        }
    }

    for m in BASE64_RE.find_iter(text) {
        let candidate = m.as_str();
        if let Ok(decoded) = BASE64.decode(candidate) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                let decoded_lower = decoded_str.to_lowercase();
                let mut detected_credential = false;
                for phrase in DANGEROUS_DECODED {
                    if decoded_lower.contains(phrase) {
                        detections.push(ScanDetection {
                            scanner: "credentials".to_string(),
                            rule: "base64_encoded_injection".to_string(),
                            matched: format!(
                                "base64 decodes to: {}",
                                &decoded_str[..60.min(decoded_str.len())]
                            ),
                        });
                        detected_credential = true;
                        break;
                    }
                }
                if !detected_credential {
                    if decoded_str.starts_with("sk-")
                        || decoded_lower.starts_with("ghp_")
                        || decoded_lower.starts_with("akiah")
                        || decoded_lower.contains("aws_secret")
                    {
                        detections.push(ScanDetection {
                            scanner: "credentials".to_string(),
                            rule: "base64_encoded_credential".to_string(),
                            matched: format!(
                                "base64 decodes to: {}",
                                &decoded_str[..60.min(decoded_str.len())]
                            ),
                        });
                    }
                }
            }
        }
    }

    if let Some(m) = UNICODE_IGNORE.find(text) {
        detections.push(ScanDetection {
            scanner: "credentials".to_string(),
            rule: "unicode_homoglyph_injection".to_string(),
            matched: m.as_str().to_string(),
        });
    }

    if let Some(m) = UNICODE_IGNORE_FULL.find(text) {
        detections.push(ScanDetection {
            scanner: "credentials".to_string(),
            rule: "unicode_homoglyph_injection".to_string(),
            matched: m.as_str().to_string(),
        });
    }

    detections
}
