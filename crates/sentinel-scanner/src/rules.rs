use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use thiserror::Error;

use sentinel_ast::query_pattern;
use sentinel_core::{Finding, Severity};
use sentinel_taint::TaintEngine;

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

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
    pub mode: Option<String>,
    pub pattern: Option<String>,
    pub patterns: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
    pub pattern_not: Option<String>,
    pub pattern_not_inside: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(rename = "pattern-sources")]
    pub pattern_sources: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-sinks")]
    pub pattern_sinks: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-sanitizers")]
    pub pattern_sanitizers: Option<Vec<PatternEntry>>,
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,
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
        metavariable_pattern: Option<Box<serde_yaml::Value>>,
        #[serde(rename = "pattern-regex")]
        pattern_regex: Option<String>,
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

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(RuleError::Parse("rule id is empty".to_string()));
        }
        if self.message.trim().is_empty() {
            return Err(RuleError::Parse(format!(
                "rule {} has empty message",
                self.id
            )));
        }
        if self.languages.is_empty() {
            return Err(RuleError::Parse(format!(
                "rule {} has no languages",
                self.id
            )));
        }
        match self.severity.to_lowercase().as_str() {
            s if [
                "error", "warning", "info", "medium", "high", "low", "critical",
            ]
            .contains(&s) => {}
            _ => {
                return Err(RuleError::Parse(format!(
                    "rule {} has unknown severity: {}",
                    self.id, self.severity
                )))
            }
        }
        if let Some(mode) = &self.mode {
            match mode.as_str() {
                "taint" => {}
                "grep" | "search" => {}
                _ => {
                    return Err(RuleError::Parse(format!(
                        "rule {} has unsupported mode: {}",
                        self.id, mode
                    )))
                }
            }
        }
        if let Some(re) = &self.pattern_regex {
            Regex::new(re).map_err(|e| {
                RuleError::Parse(format!("rule {} has invalid regex: {}", self.id, e))
            })?;
        }
        Ok(())
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn load_from_dir(dir: &str) -> Result<Self> {
        let mut rules = Vec::new();
        Self::load_rules_from_dir(dir, &mut rules)?;
        Self::compile_and_validate(&mut rules)?;
        Ok(Self { rules })
    }

    pub fn load_from_embedded() -> Self {
        let mut rules = Vec::new();
        for (_, contents) in embedded_rules() {
            if let Ok(rule_set) = RuleSet::from_yaml(contents) {
                rules.extend(rule_set.rules);
            }
        }
        let _ = Self::compile_and_validate(&mut rules);
        Self { rules }
    }

    pub fn load_from_embedded_validated() -> Result<Self> {
        let mut rules = Vec::new();
        let mut errors = Vec::new();
        for (path, contents) in embedded_rules() {
            match RuleSet::from_yaml(contents) {
                Ok(rule_set) => rules.extend(rule_set.rules),
                Err(e) => errors.push(format!("{}: {}", path, e)),
            }
        }
        if !errors.is_empty() {
            return Err(RuleError::Parse(errors.join("\n")));
        }
        Self::compile_and_validate(&mut rules)?;
        Ok(Self { rules })
    }

    fn compile_and_validate(rules: &mut [Rule]) -> Result<()> {
        for rule in rules.iter_mut() {
            if let Some(re) = &rule.pattern_regex {
                if let Ok(compiled) = Regex::new(re) {
                    rule.compiled_regex = Some(compiled);
                }
            }
            rule.validate()?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn load_rules_from_dir(dir: &str, rules: &mut Vec<Rule>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::load_rules_from_dir(
                    path.to_str()
                        .ok_or_else(|| RuleError::Parse("invalid path".to_string()))?,
                    rules,
                )?;
            } else if path
                .extension()
                .map(|e| e == "yml" || e == "yaml")
                .unwrap_or(false)
            {
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
            if !rule.languages.is_empty()
                && !rule.languages.contains(&language.to_string())
                && !rule.languages.contains(&"regex".to_string())
            {
                continue;
            }

            if rule.mode.as_deref() == Some("taint") {
                if rule.languages.is_empty() || rule.languages.contains(&language.to_string()) {
                    let mut hits = self.analyze_taint_rule(rule, source, file_path);
                    findings.append(&mut hits);
                }
                continue;
            }

            if self.matches(rule, source) {
                let line = find_first_line(
                    source,
                    rule.pattern
                        .as_deref()
                        .or_else(|| rule.patterns.as_ref().and_then(|p| first_pattern(p)))
                        .or_else(|| rule.pattern_either.as_ref().and_then(|p| first_pattern(p)))
                        .or(rule.pattern_regex.as_deref())
                        .unwrap_or(""),
                );
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
        let mut seen = HashSet::new();
        findings.retain(|f| {
            let key = (f.file.clone(), f.line, f.title.clone());
            seen.insert(key)
        });
        findings
    }

    fn analyze_taint_rule(&self, rule: &Rule, source: &str, file_path: &Path) -> Vec<Finding> {
        let sources = extract_pattern_strings(rule.pattern_sources.as_deref());
        let sinks = extract_pattern_strings(rule.pattern_sinks.as_deref());
        let sanitizers = extract_pattern_strings(rule.pattern_sanitizers.as_deref());

        if sinks.is_empty() {
            return Vec::new();
        }

        let engine = TaintEngine::new(sources, sinks, sanitizers);
        engine.analyze_file(source, file_path, &rule.id, &rule.message, rule.severity())
    }

    fn matches(&self, rule: &Rule, source: &str) -> bool {
        if let Some(pattern_regex) = &rule.pattern_regex {
            if let Ok(re) = Regex::new(pattern_regex) {
                if re.is_match(source) {
                    return true;
                }
            }
        }
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

fn extract_pattern_strings(entries: Option<&[PatternEntry]>) -> Vec<String> {
    let mut result = Vec::new();
    if let Some(entries) = entries {
        for entry in entries {
            extract_from_entry(entry, &mut result);
        }
    }
    result
}

fn extract_from_entry(entry: &PatternEntry, result: &mut Vec<String>) {
    match entry {
        PatternEntry::Simple(text) => {
            let trimmed = text.trim();
            if !trimmed.is_empty() && !trimmed.contains("$") {
                result.push(trimmed.to_string());
            }
        }
        PatternEntry::Complex {
            pattern,
            patterns,
            pattern_either,
            ..
        } => {
            if let Some(p) = pattern {
                let trimmed = p.trim();
                if !trimmed.is_empty() && !trimmed.contains("$") {
                    result.push(trimmed.to_string());
                }
            }
            if let Some(ps) = patterns {
                for entry in ps {
                    extract_from_entry(entry, result);
                }
            }
            if let Some(pe) = pattern_either {
                for entry in pe {
                    extract_from_entry(entry, result);
                }
            }
        }
    }
}

fn first_pattern(patterns: &[PatternEntry]) -> Option<&str> {
    for p in patterns {
        match p {
            PatternEntry::Simple(s) => return Some(s),
            PatternEntry::Complex {
                pattern,
                pattern_regex,
                ..
            } => {
                if let Some(s) = pattern {
                    return Some(s);
                }
                if let Some(s) = pattern_regex {
                    return Some(s);
                }
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
        PatternEntry::Complex {
            pattern,
            patterns,
            pattern_either,
            pattern_not,
            pattern_not_inside,
            pattern_inside,
            pattern_regex,
            ..
        } => {
            let mut has_positive = false;
            if let Some(p) = pattern_regex {
                has_positive = true;
                if let Ok(re) = Regex::new(p) {
                    if !re.is_match(source) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
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
        let normalized = lang.as_str();
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
    if let Ok(re) = Regex::new(pattern) {
        if let Some(mat) = re.find(source) {
            let line = source[..mat.start()].lines().count() + 1;
            return line;
        }
    }
    source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(pattern))
        .map(|(i, _)| i + 1)
        .unwrap_or(1)
}

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_yaml(contents: &str) -> Result<Self> {
        let rule_set: RuleSet =
            serde_yaml::from_str(contents).map_err(|e| RuleError::Parse(format!("{}", e)))?;
        Ok(rule_set)
    }
}
