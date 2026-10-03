use anyhow::Result;
use sentinel_llm::OllamaClient;

pub fn explain(finding_id: String) -> Result<()> {
    let db = match sentinel_db::SentinelDb::new(".sentinel.db") {
        Ok(db) => db,
        Err(_) => {
            println!("No local database found. Run `sentinel audit` first.");
            return Ok(());
        }
    };

    match db.get_finding(&finding_id) {
        Ok(Some(finding)) => {
            let client = OllamaClient::new(sentinel_llm::ProviderConfig {
                endpoint: "http://localhost:11434".to_string(),
                model: "llama2".to_string(),
                api_key: None,
            });
            match client.explain_finding(&finding) {
                Ok(explanation) => {
                    println!("Finding: {}", finding.title);
                    println!("Severity: {}", finding.severity);
                    println!("File: {}:{}", finding.file.display(), finding.line);
                    println!("\nExplanation:\n{}", explanation);
                }
                Err(_) => {
                    println!("Finding: {}", finding.title);
                    println!("Severity: {}", finding.severity);
                    println!("File: {}:{}", finding.file.display(), finding.line);
                    println!("LLM explanation not available. Ensure Ollama is running.");
                }
            }
        }
        Ok(None) => {
            println!("Finding not found: {}", finding_id);
        }
        Err(_) => {
            println!("Error retrieving finding: {}", finding_id);
        }
    }

    Ok(())
}
