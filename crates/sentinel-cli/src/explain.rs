use anyhow::Result;
use std::path::PathBuf;
pub fn explain(id: String) -> Result<i32> {
    explain_at(id, PathBuf::from("."), None)
}
pub fn explain_at(id: String, project: PathBuf, override_path: Option<PathBuf>) -> Result<i32> {
    let path = crate::scan::database_path(&project, override_path.as_deref());
    let db = sentinel_db::SentinelDb::open_existing(&path)?;
    let finding = db
        .get_finding(&id)?
        .ok_or_else(|| anyhow::anyhow!("finding not found: {id}"))?;
    let client = sentinel_llm::OllamaClient::new(sentinel_llm::ProviderConfig {
        endpoint: "http://localhost:11434".into(),
        model: "llama2".into(),
        api_key: None,
    });
    println!(
        "Finding: {}\nSeverity: {}\nFile: {}:{}\n\n{}",
        finding.title,
        finding.severity,
        finding.file.display(),
        finding.line,
        client.explain_finding(&finding)?
    );
    Ok(0)
}
