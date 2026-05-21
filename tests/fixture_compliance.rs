use wevibe_guard::{flag_action_proximate, scan_memory_structured};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

fn load_fixtures(filename: &str) -> Vec<Value> {
    let base = env!("CARGO_MANIFEST_DIR");
    let path = format!("{}/tests/{}", base, filename);
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Cannot read fixture file: {}", path));
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn all_bad_fixtures_detect() {
    let fixtures = load_fixtures("fixtures_bad.json");
    assert!(!fixtures.is_empty(), "fixtures_bad.json is empty");
    for fixture in &fixtures {
        let text = fixture["memory"]["text"].as_str().unwrap();
        let keywords: Vec<String> = fixture["memory"]["keywords"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let mut metadata = HashMap::new();
        if let Some(obj) = fixture["memory"]["metadata"].as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    metadata.insert(k.clone(), s.to_string());
                }
            }
        }
        let result = scan_memory_structured(text, &keywords, &metadata);
        assert!(
            !result.passed,
            "MISSED DETECTION — fixture: {}\nDetections: {:?}",
            fixture["id"].as_str().unwrap_or("no id"),
            result.detections
        );
    }
}

#[test]
fn zero_false_positives_on_good_fixtures() {
    let fixtures = load_fixtures("fixtures_good.json");
    assert!(!fixtures.is_empty(), "fixtures_good.json is empty");
    for fixture in &fixtures {
        let text = fixture["memory"]["text"].as_str().unwrap();
        let keywords: Vec<String> = fixture["memory"]["keywords"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let mut metadata = HashMap::new();
        if let Some(obj) = fixture["memory"]["metadata"].as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    metadata.insert(k.clone(), s.to_string());
                }
            }
        }
        let result = scan_memory_structured(text, &keywords, &metadata);
        assert!(
            result.passed,
            "FALSE POSITIVE — fixture: {}\nDetections: {:?}",
            fixture["id"].as_str().unwrap_or("no id"),
            result.detections
        );
    }
}

#[test]
fn redteam_fixtures_match_expected() {
    let fixtures = load_fixtures("fixtures_redteam.json");
    assert!(!fixtures.is_empty(), "fixtures_redteam.json is empty");
    for (i, fixture) in fixtures.iter().enumerate() {
        let expected = fixture["expected_result"].as_str().unwrap();
        let text = fixture["memory"]["text"].as_str().unwrap();
        let keywords: Vec<String> = fixture["memory"]["keywords"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let mut metadata = HashMap::new();
        if let Some(obj) = fixture["memory"]["metadata"].as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    metadata.insert(k.clone(), s.to_string());
                }
            }
        }
        let result = scan_memory_structured(text, &keywords, &metadata);
        match expected {
            "fail" => {
                if result.passed {
                    eprintln!(
                        "MISSED DETECTION idx={} attack_type={} text={}",
                        i,
                        fixture["attack_type"].as_str().unwrap_or(""),
                        fixture["memory"]["text"].as_str().unwrap_or("")
                    );
                }
                assert!(
                    !result.passed,
                    "Expected detection — fixture: {}",
                    fixture["attack_type"].as_str().unwrap_or("")
                );
            }
            "pass" => assert!(
                result.passed,
                "Unexpected detection — fixture: {}\nDetections: {:?}",
                fixture["attack_type"].as_str().unwrap_or(""),
                result.detections
            ),
            _ => panic!("Unknown expected_result: {}", expected),
        }
        if let Some(expected_flags) = fixture.get("expected_flags") {
            let stack: Vec<&str> = fixture["stack"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let flags = flag_action_proximate(text, &stack);
            let expected: Vec<String> = expected_flags
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            for ef in &expected {
                assert!(
                    flags.flags.contains(ef),
                    "Missing flag '{}' — fixture: {}",
                    ef,
                    fixture["attack_type"].as_str().unwrap_or("")
                );
            }
        }
    }
}
