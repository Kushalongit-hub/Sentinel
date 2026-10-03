use std::fs;
use std::path::Path;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use serde_yaml;

use sentinel_ast::query_pattern;
use sentinel_core::{Finding, Severity};

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, RuleError>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub message: String,
    pub languages: Vec<String>,
    pub severity: String,
    pub pattern: Option<String>,
    pub patterns: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
    pub pattern_not: Option<String>,
    pub pattern_not_inside: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PatternEntry {
    Simple(String),
    Complex {
        pattern: Option<String>,
        patterns: Option<Vec<PatternEntry>>,
        #[serde(rename = "pattern-either")]
        pattern_either: Option<Vec<PatternEntry>>,
        pattern_not: Option<String>,
        pattern_not_inside: Option<String>,
        #[serde(rename = "pattern-inside")]
        pattern_inside: Option<String>,
        #[serde(rename = "focus-metavariable")]
        focus_metavariable: Option<String>,
        #[serde(rename = "metavariable-pattern")]
        metavariable_pattern: Option<serde_yaml::Value>,
    },
}

impl Rule {
    pub fn severity(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "error" => Severity::Critical,
            "warning" => Severity::High,
            "info" => Severity::Info,
            _ => Severity::Medium,
        }
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn load_from_dir(dir: &str) -> Result<Self> {
        let mut rules = Vec::new();
        Self::load_rules_from_dir(dir, &mut rules)?;
        Ok(Self { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    fn load_rules_from_dir(dir: &str, rules: &mut Vec<Rule>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::load_rules_from_dir(path.to_str().ok_or_else(|| RuleError::Parse("invalid path".to_string()))?, rules)?;
            } else if path.extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false) {
                let contents = fs::read_to_string(&path)?;
                let rule_set: RuleSet = serde_yaml::from_str(&contents)
                    .map_err(|e| RuleError::Parse(format!("{}: {}", path.display(), e)))?;
                rules.extend(rule_set.rules);
            }
        }
        Ok(())
    }

    pub fn scan(&self, language: &str, source: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            if !rule.languages.is_empty() && !rule.languages.contains(&language.to_string()) && !rule.languages.contains(&"regex".to_string()) {
                continue;
            }
            if self.matches(rule, source) {
                let line = find_first_line(source, rule.pattern.as_deref().or_else(|| {
                    rule.patterns.as_ref().and_then(|p| first_pattern(p))
                }).or_else(|| rule.pattern_either.as_ref().and_then(|p| first_pattern(p))).unwrap_or(""));
                findings.push(Finding {
                    id: format!("{}-{}", rule.id, uuid::Uuid::new_v4().simple()),
                    severity: rule.severity(),
                    confidence: 0.7,
                    category: "rule".to_string(),
                    file: file_path.to_path_buf(),
                    line,
                    title: rule.id.clone(),
                    description: rule.message.clone(),
                    execution_path: Vec::new(),
                    affected_components: Vec::new(),
                    evidence: Vec::new(),
                    recommendation: String::new(),
                });
            }
        }
        findings
    }

    fn matches(&self, rule: &Rule, source: &str) -> bool {
        if let Some(pattern) = &rule.pattern {
            if pattern.contains("...") {
                if ast_matches(source, &rule.languages, pattern) {
                    return true;
                }
            } else if source.contains(pattern) {
                return true;
            }
        }
        if let Some(patterns) = &rule.patterns {
            if matches_all(patterns, source, &rule.languages) {
                return true;
            }
        }
        if let Some(alternatives) = &rule.pattern_either {
            if matches_any(alternatives, source, &rule.languages) {
                return true;
            }
        }
        false
    }
}

fn first_pattern(patterns: &[PatternEntry]) -> Option<&str> {
    for p in patterns {
        if let PatternEntry::Simple(s) = p {
            return Some(s);
        }
        if let PatternEntry::Complex { pattern, .. } = p {
            if let Some(s) = pattern {
                return Some(s);
            }
        }
    }
    None
}

fn matches_all(patterns: &[PatternEntry], source: &str, languages: &[String]) -> bool {
    patterns.iter().all(|p| matches_one(p, source, languages))
}

fn matches_any(patterns: &[PatternEntry], source: &str, languages: &[String]) -> bool {
    patterns.iter().any(|p| matches_one(p, source, languages))
}

fn matches_one(entry: &PatternEntry, source: &str, languages: &[String]) -> bool {
    match entry {
        PatternEntry::Simple(text) => {
            if text.contains("...") {
                ast_matches(source, languages, text)
            } else {
                source.contains(text)
            }
        }
        PatternEntry::Complex { pattern, patterns, pattern_either, pattern_not, pattern_not_inside, pattern_inside, .. } => {
            let mut has_positive = false;
            if let Some(p) = pattern {
                has_positive = true;
                if p.contains("...") {
                    if !ast_matches(source, languages, p) {
                        return false;
                    }
                } else if !source.contains(p) {
                    return false;
                }
            }
            if let Some(ps) = patterns {
                has_positive = true;
                if !matches_all(ps, source, languages) {
                    return false;
                }
            }
            if let Some(pe) = pattern_either {
                has_positive = true;
                if !matches_any(pe, source, languages) {
                    return false;
                }
            }
            if !has_positive {
                return false;
            }
            if let Some(pn) = pattern_not {
                if pn.contains("...") {
                    if ast_matches(source, languages, pn) {
                        return false;
                    }
                } else if source.contains(pn) {
                    return false;
                }
            }
            if let Some(pni) = pattern_not_inside {
                if pni.contains("...") {
                    if ast_matches(source, languages, pni) {
                        return false;
                    }
                } else if source.contains(pni) {
                    return false;
                }
            }
            if let Some(pi) = pattern_inside {
                if pi.contains("...") {
                    if !ast_matches(source, languages, pi) {
                        return false;
                    }
                } else if !source.contains(pi) {
                    return false;
                }
            }
            true
        }
    }
}

fn ast_matches(source: &str, languages: &[String], pattern: &str) -> bool {
    if languages.is_empty() {
        return false;
    }
    for lang in languages {
        if lang == "regex" {
            continue;
        }
        let normalized = match lang.as_str() {
            "typescript" => "typescript",
            "javascript" => "javascript",
            other => other,
        };
        if let Ok(true) = query_pattern(source.as_bytes(), normalized, pattern) {
            return true;
        }
    }
    false
}

fn find_first_line(source: &str, pattern: &str) -> usize {
    if pattern.is_empty() {
        return 1;
    }
    source.lines().enumerate().find(|(_, line)| line.contains(pattern)).map(|(i, _)| i + 1).unwrap_or(1)
}

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}
