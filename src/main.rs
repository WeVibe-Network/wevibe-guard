use wevibe_guard::{flag_action_proximate, scan_memory_structured, FieldDetection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read};
use std::process;

#[derive(Deserialize)]
struct Request {
    memory: MemoryInput,
    stack: Option<Vec<String>>,
    include_flags: Option<bool>,
}

#[derive(Deserialize)]
struct MemoryInput {
    text: String,
    keywords: Option<Vec<String>>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct Response {
    passed: bool,
    detections: Vec<FieldDetection>,
    flags: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    passed: bool,
}

const MAX_INPUT_BYTES: usize = 1_048_576;

fn main() {
    let mut input = String::new();

    match io::stdin()
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_string(&mut input)
    {
        Ok(_) => {}
        Err(e) => {
            let err = ErrorResponse {
                error: format!("failed to read stdin: {}", e),
                passed: false,
            };
            println!("{}", serde_json::to_string(&err).unwrap_or_default());
            process::exit(1);
        }
    }

    if input.len() > MAX_INPUT_BYTES {
        let err = ErrorResponse {
            error: format!("input exceeds maximum size of {} bytes", MAX_INPUT_BYTES),
            passed: false,
        };
        println!("{}", serde_json::to_string(&err).unwrap_or_default());
        process::exit(1);
    }

    let input_clone = input.trim().to_string();

    let req: Request = match serde_json::from_str(&input_clone) {
        Ok(r) => r,
        Err(e) => {
            let err = ErrorResponse {
                error: format!("invalid JSON input: {}", e),
                passed: false,
            };
            println!("{}", serde_json::to_string(&err).unwrap_or_default());
            process::exit(1);
        }
    };

    let scan_result = scan_memory_structured(
        &req.memory.text,
        req.memory.keywords.as_deref().unwrap_or(&[]),
        req.memory.metadata.as_ref().unwrap_or(&HashMap::new()),
    );

    let flags = if req.include_flags.unwrap_or(false) {
        let stack: Vec<&str> = req
            .stack
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();
        Some(flag_action_proximate(&req.memory.text, &stack).flags)
    } else {
        None
    };

    let response = Response {
        passed: scan_result.passed,
        detections: scan_result.detections,
        flags,
    };

    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|e| {
            eprintln!("failed to serialize response: {}", e);
            r#"{"passed":false,"detections":[],"flags":null}"#.to_string()
        })
    );
}
