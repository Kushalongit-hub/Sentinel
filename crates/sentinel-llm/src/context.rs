use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_READ_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolSummary {
    pub name: String,
    pub kind: String,
    pub line: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub language: Option<String>,
    pub sha256: String,
    pub lines: usize,
    pub symbols: Vec<SymbolSummary>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceExcerpt {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectContext {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub files: Vec<FileSummary>,
    pub excerpts: Vec<SourceExcerpt>,
    pub coverage_notes: Vec<String>,
}

fn eligible(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if name.starts_with('.')
        || name.contains("secret")
        || name.contains("credential")
        || name.ends_with(".pem")
        || name.ends_with(".key")
    {
        return false;
    }
    sentinel_ast::detect_language(path).is_some()
        || matches!(
            name.as_str(),
            "cargo.toml" | "package.json" | "pyproject.toml" | "go.mod" | "requirements.txt"
        )
        || path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}

/// Build one bounded evidence bundle, reused verbatim by every provider in a request.
/// This is lexical retrieval, not a resolved call graph or embedding index.
pub fn build_context(
    root: &Path,
    question: &str,
    focus: Option<&Path>,
) -> crate::Result<ProjectContext> {
    build_context_with_budget(root, question, focus.map(|p| (p, 1)), MAX_CONTEXT_BYTES)
}
pub fn build_context_with_budget(
    root: &Path,
    question: &str,
    focus: Option<(&Path, usize)>,
    max_bytes: usize,
) -> crate::Result<ProjectContext> {
    if !(1024..=MAX_CONTEXT_BYTES).contains(&max_bytes) {
        return Err(crate::LlmError::Configuration(
            "context budget must be 1024 to 65536 bytes".into(),
        ));
    }
    let root = root
        .canonicalize()
        .map_err(|e| crate::LlmError::Configuration(e.to_string()))?;
    if !root.is_dir() {
        return Err(crate::LlmError::Configuration(
            "project context requires a directory".into(),
        ));
    }
    let focus_line = focus.map(|(_, line)| line);
    let focus = focus.and_then(|(p, _)| p.canonicalize().ok());
    let mut paths = sentinel_ast::walk(
        root.to_str()
            .ok_or_else(|| crate::LlmError::Configuration("invalid project path".into()))?,
    )
    .map_err(|e| crate::LlmError::Configuration(e.to_string()))?
    .into_iter()
    .filter(|e| eligible(&e.path))
    .map(|e| e.path)
    .collect::<Vec<_>>();
    paths.sort_by_key(|p| {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let priority = if focus.as_ref() == Some(p) {
            0
        } else if matches!(
            name.as_str(),
            "readme.md" | "cargo.toml" | "package.json" | "pyproject.toml"
        ) {
            1
        } else {
            2
        };
        (priority, p.clone())
    });
    let mut context = ProjectContext {
        schema_version: 1,
        snapshot_id: String::new(),
        files: vec![],
        excerpts: vec![],
        coverage_notes: vec![],
    };
    if paths.len() > MAX_FILES {
        context.coverage_notes.push(format!(
            "file inventory limited to {MAX_FILES} eligible files"
        ));
        paths.truncate(MAX_FILES);
    }
    let words = question
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .collect::<std::collections::BTreeSet<_>>();
    let extractor = sentinel_ast::SymbolExtractor::new();
    let mut read_bytes = 0;
    let mut candidates = vec![];
    for path in paths {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let canonical = match path.canonicalize() {
            Ok(p) if p.starts_with(&root) => p,
            _ => {
                context.coverage_notes.push(format!(
                    "outside-project or inaccessible path skipped: {relative}"
                ));
                continue;
            }
        };
        let mut bytes = vec![];
        match std::fs::File::open(&canonical)
            .and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        {
            Ok(_) => {}
            Err(_) => {
                context
                    .coverage_notes
                    .push(format!("unreadable file: {relative}"));
                continue;
            }
        }
        read_bytes += bytes.len();
        if read_bytes > MAX_READ_BYTES {
            context
                .coverage_notes
                .push("source read budget reached (4 MiB)".into());
            break;
        }
        if bytes.len() as u64 > MAX_FILE_BYTES {
            context
                .coverage_notes
                .push(format!("source file exceeds 256 KiB: {relative}"));
            continue;
        }
        let source = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                context
                    .coverage_notes
                    .push(format!("non-UTF-8 file skipped: {relative}"));
                continue;
            }
        };
        let language = sentinel_ast::detect_language(&path);
        let symbols = if language.as_deref().is_some_and(|l| l != "go") {
            match extractor.extract(&path, source.as_bytes()) {
                Ok(s) => {
                    if s.len() > 128 {
                        context
                            .coverage_notes
                            .push(format!("symbol inventory truncated: {relative}"));
                    }
                    s.into_iter()
                        .take(128)
                        .map(|s| SymbolSummary {
                            name: s.name,
                            kind: s.kind,
                            line: s.line,
                        })
                        .collect()
                }
                Err(_) => {
                    context
                        .coverage_notes
                        .push(format!("syntax could not be indexed: {relative}"));
                    vec![]
                }
            }
        } else {
            vec![]
        };
        let score = words
            .iter()
            .filter(|w| relative.to_lowercase().contains(w.as_str()))
            .count()
            * 10
            + words
                .iter()
                .filter(|w| source.to_lowercase().contains(w.as_str()))
                .count();
        let score = score
            + if focus.as_ref() == Some(&canonical) {
                1000
            } else {
                0
            }
            + if relative.to_lowercase().ends_with("readme.md")
                || relative.ends_with("Cargo.toml")
                || relative.ends_with("package.json")
            {
                5
            } else {
                0
            };
        context.files.push(FileSummary {
            path: relative.clone(),
            language,
            sha256: format!("{:x}", Sha256::digest(source.as_bytes())),
            lines: source.lines().count(),
            symbols,
        });
        candidates.push((score, relative, source));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    if serde_json::to_vec(&context).unwrap().len() > max_bytes / 2 {
        context.coverage_notes.insert(
            0,
            "metadata trimmed to reserve space for source excerpts".into(),
        );
        while serde_json::to_vec(&context).unwrap().len() > max_bytes / 2 {
            if context.files.pop().is_none() {
                context.coverage_notes.pop();
            }
        }
    }
    for (_, path, source) in candidates.into_iter().take(20) {
        let lines = source.lines().collect::<Vec<_>>();
        let anchor = if focus.as_ref().is_some_and(|p| {
            p.strip_prefix(&root)
                .is_ok_and(|p| p.to_string_lossy().replace('\\', "/") == path)
        }) {
            focus_line
                .unwrap_or(1)
                .saturating_sub(1)
                .min(lines.len().saturating_sub(1))
        } else {
            lines
                .iter()
                .enumerate()
                .max_by_key(|(_, line)| {
                    words
                        .iter()
                        .filter(|w| line.to_lowercase().contains(w.as_str()))
                        .count()
                })
                .filter(|(_, line)| {
                    words
                        .iter()
                        .any(|w| line.to_lowercase().contains(w.as_str()))
                })
                .map(|(i, _)| i)
                .unwrap_or(0)
        };
        let start = anchor.saturating_sub(8);
        let mut text = String::new();
        let mut end = start;
        for (i, line) in lines.iter().enumerate().skip(start).take(40) {
            let fragment = format!("{}: {}\n", i + 1, line);
            if text.len() + fragment.len() > 2500 {
                break;
            }
            text.push_str(&fragment);
            end = i + 1;
        }
        if !text.is_empty() {
            context.excerpts.push(SourceExcerpt {
                path,
                start_line: start + 1,
                end_line: end,
                text,
            });
        }
    }
    context.coverage_notes.push("Context uses bounded lexical retrieval; excerpts are partial and relationships are not a resolved call graph.".into());
    // Leave space for the fixed-length snapshot ID after hashing.
    if serde_json::to_vec(&context).unwrap().len() + 64 > max_bytes {
        context.coverage_notes.push(format!(
            "context serialization trimmed to {max_bytes} bytes"
        ));
    }
    while serde_json::to_vec(&context).unwrap().len() + 64 > max_bytes {
        if context.excerpts.pop().is_none() && context.files.pop().is_none() {
            context.coverage_notes.pop();
        }
    }
    context.snapshot_id = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&context).unwrap())
    );
    Ok(context)
}
