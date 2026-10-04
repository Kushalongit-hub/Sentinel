pub mod error;
pub mod models;

pub use error::{Result, SentinelError};
pub use models::{
    Finding, ScanOutcome, ScannerOutcome, ScannerResult, ScanReport, Severity, ThresholdConfig,
};
