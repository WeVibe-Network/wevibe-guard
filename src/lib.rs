pub mod credentials;
pub mod exfiltration;
pub mod flags;
pub mod scanner;

pub use flags::FlagResult;
pub use scanner::{flag_action_proximate, scan_memory, scan_memory_structured, FieldDetection, ScanDetection, ScanResult, StructuredScanResult};

pub fn init() {
    println!("hello world");
}
