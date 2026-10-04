pub mod error;
pub mod models;

pub use error::{Result, SentinelError};
pub use models::{
    Finding, ScanOutcome, ScanReport, ScannerOutcome, ScannerResult, Severity, ThresholdConfig,
};
