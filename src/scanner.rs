use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use yara_x::{Compiler, Rules};

use crate::credentials;
use crate::exfiltration;
use crate::flags::FlagResult;

static YARA_RULES: Lazy<Rules> = Lazy::new(|| {
    let yar_src = include_str!("rules/injection.yar");
    let mut compiler = Compiler::new();
    compiler
        .add_source(yar_src)
        // SAFETY: compile-time invariant — hardcoded YARA source; failure prevents binary from functioning at all
        .expect("injection.yar failed to compile under YARA-X");
    compiler.build()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetection {
    pub scanner: String,
    pub rule: String,
    pub matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub passed: bool,
    pub detections: Vec<ScanDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDetection {
    pub field: String,
    pub scanner: String,
    pub rule: String,
    pub matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredScanResult {
    pub passed: bool,
    pub detections: Vec<FieldDetection>,
}

pub fn scan_memory(text: &str) -> ScanResult {
    let mut detections: Vec<ScanDetection> = Vec::new();

    detections.extend(_scan_yara(text));
    detections.extend(_scan_credentials(text));
    detections.extend(_scan_exfiltration(text));

    deduplicate_detections(&mut detections);

    ScanResult {
        passed: detections.is_empty(),
        detections,
    }
}

pub fn scan_memory_structured(
    text: &str,
    keywords: &[String],
    metadata: &std::collections::HashMap<String, String>,
) -> StructuredScanResult {
    let mut detections: Vec<FieldDetection> = Vec::new();

    let text_result = scan_memory(text);
    for d in text_result.detections {
        detections.push(FieldDetection {
            field: "text".to_string(),
            scanner: d.scanner,
            rule: d.rule,
            matched: d.matched,
        });
    }

    for (i, kw) in keywords.iter().enumerate() {
        let kw_result = scan_memory(kw);
        for d in kw_result.detections {
            detections.push(FieldDetection {
                field: format!("keywords[{}]", i),
                scanner: d.scanner,
                rule: d.rule,
                matched: d.matched,
            });
        }
    }

    let mut sorted_keys: Vec<&String> = metadata.keys().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        let val = &metadata[key];
        let meta_result = scan_memory(val);
        for d in meta_result.detections {
            detections.push(FieldDetection {
                field: format!("metadata.{}", key),
                scanner: d.scanner,
                rule: d.rule,
                matched: d.matched,
            });
        }
    }

    StructuredScanResult {
        passed: detections.is_empty(),
        detections,
    }
}

pub fn flag_action_proximate(text: &str, stack: &[&str]) -> FlagResult {
    crate::flags::flag_action_proximate(text, stack)
}

fn _scan_yara(text: &str) -> Vec<ScanDetection> {
    let mut results = Vec::new();
    let rules = &*YARA_RULES;
    let mut scanner = yara_x::Scanner::new(rules);

    match scanner.scan(text.as_bytes()) {
        Ok(scan_results) => {
            for rule in scan_results.matching_rules() {
                let rule_name = rule.identifier();

                results.push(ScanDetection {
                    scanner: "yara".to_string(),
                    rule: rule_name.to_string(),
                    matched: rule_name.to_string(),
                });
            }
        }
        Err(e) => {
            eprintln!("YARA scan error: {:?}", e);
        }
    }
    results
}

fn _scan_credentials(text: &str) -> Vec<ScanDetection> {
    credentials::scan(text)
}

fn _scan_exfiltration(text: &str) -> Vec<ScanDetection> {
    exfiltration::scan(text)
}

fn deduplicate_detections(detections: &mut Vec<ScanDetection>) {
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    detections.retain(|d| {
        let key = (d.scanner.clone(), d.rule.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.insert(key);
            true
        }
    });
}

impl From<ScanResult> for StructuredScanResult {
    fn from(r: ScanResult) -> Self {
        StructuredScanResult {
            passed: r.passed,
            detections: r.detections.into_iter().map(|d| FieldDetection {
                field: "text".to_string(),
                scanner: d.scanner,
                rule: d.rule,
                matched: d.matched,
            }).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_rules_compile() {
        let _ = YARA_RULES;
    }
}
