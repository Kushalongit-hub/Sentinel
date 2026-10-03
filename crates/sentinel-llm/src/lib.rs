use reqwest::blocking::Client;
use thiserror::Error;

use sentinel_core::Finding;

#[derive(Error, Debug)]
pub enum LlmError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub endpoint: String,
    pub model: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PromptTemplate {
    pub system: &'static str,
    pub user: &'static str,
}

impl Default for PromptTemplate {
    fn default() -> Self {
        Self {
            system: "You are a security code auditor.",
            user: "Analyze the following finding and provide a detailed explanation.",
        }
    }
}

pub struct OllamaClient {
    config: ProviderConfig,
    client: Client,
}

impl OllamaClient {
    pub fn new(config: ProviderConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    pub fn explain_finding(&self, finding: &Finding) -> Result<String> {
        let prompt = format!(
            "Finding ID: {}\nSeverity: {}\nConfidence: {}\nCategory: {}\nFile: {}:{}\nTitle: {}\nDescription: {}\nRecommendation: {}\n\nProvide a detailed security analysis of this finding.",
            finding.id, finding.severity, finding.confidence, finding.category,
            finding.file.display(), finding.line, finding.title, finding.description, finding.recommendation
        );

        let body = serde_json::json!({
            "model": self.config.model,
            "prompt": prompt,
            "stream": false
        });

        let url = format!(
            "{}/api/generate",
            self.config.endpoint.trim_end_matches('/')
        );
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| LlmError::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(LlmError::Provider(format!("HTTP {}", response.status())));
        }

        let json: serde_json::Value = response
            .json()
            .map_err(|e| LlmError::Parse(e.to_string()))?;
        let response_text = json
            .get("response")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        Ok(response_text)
    }
}

pub fn render_prompt(_template: &PromptTemplate, finding: &Finding) -> String {
    format!(
        "Analyze this security finding:\n\nID: {}\nSeverity: {}\nDescription: {}\nFile: {}:{}",
        finding.id,
        finding.severity,
        finding.description,
        finding.file.display(),
        finding.line
    )
}
