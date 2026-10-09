use std::io::Read;

/// Process variables win over launch-directory settings, then user settings.
pub fn load() -> anyhow::Result<()> {
    load_file(std::path::Path::new(".env"))?;
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        load_file(&std::path::PathBuf::from(home).join(".sentinel/.env"))?;
    }
    Ok(())
}

fn load_file(path: &std::path::Path) -> anyhow::Result<()> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => anyhow::bail!("cannot read Sentinel environment configuration"),
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, ".env exceeds 64 KiB");
    let settings = parse(&bytes)?;
    for (key, value) in settings {
        if !value.is_empty() && std::env::var_os(&key).is_none() {
            std::env::set_var(key, value);
        }
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    let mut settings = Vec::new();
    for entry in dotenvy::from_read_iter(bytes) {
        // Parser errors may contain secrets; expose only a fixed message.
        let (key, value) = entry.map_err(|_| anyhow::anyhow!("invalid .env syntax"))?;
        if matches!(
            key.as_str(),
            "NVIDIA_API_KEY"
                | "SENTINEL_LOCAL_ENDPOINT"
                | "SENTINEL_LOCAL_MODEL"
                | "SENTINEL_NIM_ENDPOINT"
                | "SENTINEL_NIM_MODEL"
        ) {
            anyhow::ensure!(
                !settings.iter().any(|(previous, _)| previous == &key),
                "duplicate AI setting in .env"
            );
            settings.push((key, value));
        }
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_quotes_and_restricts_keys() {
        let settings =
            parse(b"SENTINEL_LOCAL_MODEL='qwen/qwen3.5-9b'\nPATH=unsafe\nNVIDIA_API_KEY=\n")
                .unwrap();
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].1, "qwen/qwen3.5-9b");
        assert_eq!(settings[1].1, "");
    }
    #[test]
    fn rejects_duplicates_and_redacts_syntax_errors() {
        assert!(parse(b"NVIDIA_API_KEY=a\nNVIDIA_API_KEY=b").is_err());
        let error = parse(b"NVIDIA_API_KEY='fixture-secret").unwrap_err();
        assert_eq!(error.to_string(), "invalid .env syntax");
    }
}
