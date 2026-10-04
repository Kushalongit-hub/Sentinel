use anyhow::Result;
pub fn rules() -> Result<i32> {
    let engine = sentinel_scanner::RuleEngine::load_from_embedded_validated()?;
    for rule in engine.catalog() {
        println!("{} [{}] {}", rule.id, rule.severity(), rule.message);
    }
    Ok(0)
}
