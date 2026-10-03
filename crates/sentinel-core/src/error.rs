use thiserror::Error;

#[derive(Error, Debug)]
pub enum SentinelError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Scanner error: {0}")]
    Scanner(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("LLM error: {0}")]
    Llm(String),

    #[error("Report error: {0}")]
    Report(String),
}

pub type Result<T> = std::result::Result<T, SentinelError>;
