use crate::scanner::ScanDetection;
use once_cell::sync::Lazy;
use regex::Regex;

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static HTTP_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)fetch\s*\(").expect("HTTP_CALL fetch regex"),
        Regex::new(r"(?i)curl\s+").expect("HTTP_CALL curl regex"),
        Regex::new(r"(?i)wget\s+").expect("HTTP_CALL wget regex"),
        Regex::new(r"(?i)http\.get\s*\(").expect("HTTP_CALL http.get regex"),
        Regex::new(r"(?i)requests\.get\s*\(").expect("HTTP_CALL requests.get regex"),
        Regex::new(r"(?i)requests\.post\s*\(").expect("HTTP_CALL requests.post regex"),
        Regex::new(r"(?i)axios\.(get|post)\s*\(").expect("HTTP_CALL axios regex"),
        Regex::new(r"(?i)urllib\.request\.urlopen\s*\(").expect("HTTP_CALL urllib regex"),
    ]
});

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static PACKAGE_INSTALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)pip\s+install\s+.*--index-url\s+https?://")
            .expect("PKG pip index-url regex"),
        Regex::new(r"(?i)pip\s+install\s+.*--trusted-host\s+").expect("PKG pip trusted-host regex"),
        Regex::new(r"(?i)npm\s+install\s+.*--registry\s+https?://")
            .expect("PKG npm registry regex"),
        Regex::new(r"(?i)npm\s+install\s+.*--proxy\s+https?://").expect("PKG npm proxy regex"),
        Regex::new(r"(?i)yarn\s+add\s+.*--registry\s+https?://").expect("PKG yarn registry regex"),
        Regex::new(r"(?i)pnpm\s+add\s+.*--registry\s+https?://").expect("PKG pnpm registry regex"),
        Regex::new(r"(?i)go\s+get\s+[^@\s]+@[^\s]+").expect("PKG go get regex"),
        Regex::new(r"(?i)go\s+get\s+https?://").expect("PKG go get https regex"),
        Regex::new(r"(?i)go\s+get\s+github\.com/[^/]+/[^@\s]+").expect("PKG go get github regex"),
        Regex::new(r"(?i)cargo\s+add\s+.*--git\s+").expect("PKG cargo git regex"),
    ]
});

static SAFE_DOMAINS: Lazy<std::collections::HashSet<&'static str>> = Lazy::new(|| {
    let mut set = std::collections::HashSet::new();
    set.insert("github.com");
    set.insert("githubusercontent.com");
    set.insert("npmjs.org");
    set.insert("npmjs.com");
    set.insert("pypi.org");
    set.insert("pythonhosted.org");
    set.insert("crates.io");
    set.insert("stackoverflow.com");
    set.insert("developer.mozilla.org");
    set.insert("localhost");
    set.insert("127.0.0.1");
    set.insert("example.com");
    set.insert("example.org");
    set
});

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static URL_EXTRACT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://([^\s/""'`\]}>]+)"#).expect("URL_EXTRACT regex"));

pub fn scan(text: &str) -> Vec<ScanDetection> {
    let mut detections = Vec::new();

    for pattern in HTTP_CALL_PATTERNS.iter() {
        for call_match in pattern.find_iter(text) {
            let rest = &text[call_match.start()..];
            if let Some(caps) = URL_EXTRACT.captures(rest) {
                if let Some(domain_match) = caps.get(1) {
                    let domain = domain_match.as_str().to_lowercase();
                    let is_safe = SAFE_DOMAINS.iter().any(|safe| domain.ends_with(*safe));
                    if !is_safe {
                        let snippet = rest[..80.min(rest.len())].trim().to_string();
                        detections.push(ScanDetection {
                            scanner: "exfiltration".to_string(),
                            rule: "suspicious_outbound_url".to_string(),
                            matched: snippet,
                        });
                    }
                }
            }
        }
    }

    for pattern in PACKAGE_INSTALL_PATTERNS.iter() {
        if let Some(m) = pattern.find(text) {
            let snippet = text[m.start()..(m.end() + 50).min(text.len())]
                .trim()
                .to_string();
            detections.push(ScanDetection {
                scanner: "exfiltration".to_string(),
                rule: "obfuscated_install_command".to_string(),
                matched: snippet,
            });
        }
    }

    detections
}
