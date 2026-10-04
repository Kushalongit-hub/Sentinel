use regex::Regex;
use sentinel_ast::{
    compile_pattern, match_context, match_pattern, parse_tree, validate_tree, MatchSpan,
};
use sentinel_core::{Finding, Severity};
use sentinel_taint::TaintEngine;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};
use thiserror::Error;
include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));
#[derive(Error, Debug)]
pub enum RuleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid rule: {0}")]
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
    #[serde(rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(rename = "pattern-not-regex")]
    pub pattern_not_regex: Option<String>,
    #[serde(rename = "pattern-sources")]
    pub pattern_sources: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-sinks")]
    pub pattern_sinks: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-sanitizers")]
    pub pattern_sanitizers: Option<Vec<PatternEntry>>,
    pub metadata: Option<serde_yaml::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PatternEntry {
    Simple(String),
    Complex(Box<PatternFields>),
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatternFields {
    pattern: Option<String>,
    patterns: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<PatternEntry>>,
    #[serde(rename = "pattern-not")]
    pattern_not: Option<String>,
    #[serde(rename = "pattern-not-inside")]
    pattern_not_inside: Option<String>,
    #[serde(rename = "pattern-inside")]
    pattern_inside: Option<String>,
    #[serde(rename = "pattern-regex")]
    pattern_regex: Option<String>,
    #[serde(rename = "pattern-not-regex")]
    pattern_not_regex: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_yaml::Value>,
}
#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}
impl RuleSet {
    pub fn from_yaml(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).map_err(|e| RuleError::Parse(e.to_string()))
    }
}
impl Rule {
    pub fn severity(&self) -> Severity {
        self.severity.parse().expect("validated severity")
    }
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.message.trim().is_empty() {
            return Err(invalid("empty id or message"));
        }
        self.severity.parse::<Severity>().map_err(invalid)?;
        if self.languages.is_empty()
            || self.languages.iter().any(|l| {
                !matches!(
                    l.as_str(),
                    "rust" | "python" | "javascript" | "typescript" | "regex"
                )
            })
        {
            return Err(invalid("unsupported or missing language"));
        }
        if !self.extra.is_empty() {
            return Err(invalid(format!(
                "unsupported fields: {:?}",
                self.extra.keys()
            )));
        }
        if let Some(mode) = &self.mode {
            if !matches!(mode.as_str(), "taint" | "search" | "grep") {
                return Err(invalid(format!("unsupported mode {mode}")));
            }
        }
        Ok(())
    }
}
fn invalid(s: impl Into<String>) -> RuleError {
    RuleError::Parse(s.into())
}
#[derive(Debug)]
enum Expression {
    Context(Regex),
    Selector {
        regex: Regex,
        syntax: bool,
        ellipsis: bool,
    },
    All(Vec<Expression>),
    Any(Vec<Expression>),
    Not(Box<Expression>),
    Inside(Box<Expression>),
    Outside(Box<Expression>),
}
impl Expression {
    fn requires_tree(&self) -> bool {
        match self {
            Self::Selector { syntax, .. } => *syntax,
            Self::Context(_) => true,
            Self::All(xs) | Self::Any(xs) => xs.iter().any(Self::requires_tree),
            Self::Not(x) | Self::Outside(x) | Self::Inside(x) => x.requires_tree(),
        }
    }
    fn positive(&self) -> bool {
        match self {
            Self::Not(_) | Self::Outside(_) | Self::Inside(_) => false,
            Self::All(xs) | Self::Any(xs) => xs.iter().any(Self::positive),
            _ => true,
        }
    }
    fn spans(&self, source: &str, tree: Option<&tree_sitter::Tree>) -> Vec<MatchSpan> {
        match self {
            Self::Context(regex) => tree
                .map(|t| match_context(t, source.as_bytes(), regex))
                .unwrap_or_default(),
            Self::Selector {
                regex,
                syntax,
                ellipsis,
            } => {
                if *syntax || tree.is_some() {
                    tree.map(|t| match_pattern(t, source.as_bytes(), regex, *ellipsis))
                        .unwrap_or_default()
                } else {
                    regex
                        .find_iter(source)
                        .map(|m| MatchSpan {
                            start: m.start(),
                            end: m.end(),
                        })
                        .collect()
                }
            }
            Self::Any(xs) => xs.iter().flat_map(|x| x.spans(source, tree)).collect(),
            Self::All(xs) => {
                let mut positives = xs.iter().filter(|x| x.positive());
                let mut hits = positives
                    .next()
                    .map(|x| x.spans(source, tree))
                    .unwrap_or_default();
                for x in positives {
                    let other = x.spans(source, tree);
                    hits.retain(|h| other.iter().any(|o| overlap(*h, *o)));
                }
                for x in xs.iter().filter(|x| !x.positive()) {
                    match x {
                        Self::Not(inner) => {
                            let excluded = inner.spans(source, tree);
                            hits.retain(|h| !excluded.iter().any(|e| overlap(*h, *e)));
                        }
                        Self::Outside(inner) => {
                            let excluded = inner.spans(source, tree);
                            hits.retain(|h| !excluded.iter().any(|e| e.contains(*h)));
                        }
                        Self::Inside(inner) => {
                            let required = inner.spans(source, tree);
                            hits.retain(|h| required.iter().any(|e| e.contains(*h)));
                        }
                        _ => {}
                    }
                }
                hits
            }
            _ => vec![],
        }
    }
}
fn overlap(a: MatchSpan, b: MatchSpan) -> bool {
    a.start < b.end && b.start < a.end
}
fn literal(s: &str) -> Result<Expression> {
    Ok(Expression::Selector {
        regex: compile_pattern(s).map_err(|e| invalid(e.to_string()))?,
        syntax: true,
        ellipsis: s.contains("..."),
    })
}
fn regex(s: &str) -> Result<Expression> {
    Ok(Expression::Selector {
        regex: Regex::new(s).map_err(|e| invalid(e.to_string()))?,
        syntax: false,
        ellipsis: false,
    })
}
fn context(s: &str) -> Result<Expression> {
    let regex = compile_pattern(s).map_err(|e| invalid(e.to_string()))?;
    Ok(Expression::Context(
        Regex::new(&format!(r"^\s*(?:{})", regex.as_str())).map_err(|e| invalid(e.to_string()))?,
    ))
}
fn entry(e: &PatternEntry) -> Result<Expression> {
    match e {
        PatternEntry::Simple(s) => literal(s),
        PatternEntry::Complex(value) => {
            let PatternFields {
                pattern,
                patterns,
                pattern_either,
                pattern_not,
                pattern_not_inside,
                pattern_inside,
                pattern_regex,
                pattern_not_regex,
                extra,
            } = value.as_ref();
            if !extra.is_empty() {
                return Err(invalid(format!(
                    "unsupported pattern fields: {:?}",
                    extra.keys()
                )));
            }
            fields(
                pattern.as_deref(),
                patterns.as_deref(),
                pattern_either.as_deref(),
                pattern_regex.as_deref(),
                pattern_not.as_deref(),
                pattern_not_inside.as_deref(),
                pattern_inside.as_deref(),
                pattern_not_regex.as_deref(),
            )
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn fields(
    pattern: Option<&str>,
    patterns: Option<&[PatternEntry]>,
    either: Option<&[PatternEntry]>,
    re: Option<&str>,
    not: Option<&str>,
    outside: Option<&str>,
    inside: Option<&str>,
    not_re: Option<&str>,
) -> Result<Expression> {
    let mut xs = vec![];
    if let Some(p) = pattern {
        xs.push(literal(p)?);
    }
    if let Some(p) = re {
        xs.push(regex(p)?);
    }
    if let Some(ps) = patterns {
        for p in ps {
            match entry(p)? {
                Expression::All(children) => xs.extend(children),
                x => xs.push(x),
            }
        }
    }
    if let Some(ps) = either {
        let alternatives = ps.iter().map(entry).collect::<Result<Vec<_>>>()?;
        if alternatives.is_empty() || alternatives.iter().any(|x| !x.positive()) {
            return Err(invalid("pattern-either needs positive alternatives"));
        }
        xs.push(Expression::Any(alternatives));
    }
    if let Some(p) = not {
        xs.push(Expression::Not(Box::new(literal(p)?)));
    }
    if let Some(p) = outside {
        xs.push(Expression::Outside(Box::new(context(p)?)));
    }
    if let Some(p) = inside {
        xs.push(Expression::Inside(Box::new(context(p)?)));
    }
    if let Some(p) = not_re {
        xs.push(Expression::Not(Box::new(regex(p)?)));
    }
    Ok(Expression::All(xs))
}
struct CompiledRule {
    rule: Rule,
    matcher: Option<Expression>,
    taint: Option<TaintEngine>,
}
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}
impl RuleEngine {
    pub fn load_from_dir(dir: &str) -> Result<Self> {
        let mut rules = vec![];
        load_dir(Path::new(dir), &mut rules)?;
        Self::compile(rules)
    }
    pub fn load_from_embedded_validated() -> Result<Self> {
        let mut rules = vec![];
        for (path, text) in embedded_rules() {
            rules.extend(
                RuleSet::from_yaml(text)
                    .map_err(|e| invalid(format!("{path}: {e}")))?
                    .rules,
            );
        }
        Self::compile(rules)
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    pub fn catalog(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|r| &r.rule)
    }
    fn compile(rules: Vec<Rule>) -> Result<Self> {
        let mut ids = HashSet::new();
        let mut compiled = vec![];
        for rule in rules {
            let result = (|| {
                rule.validate()?;
                if !ids.insert(rule.id.clone()) {
                    return Err(invalid("duplicate rule id"));
                }
                if rule.mode.as_deref() == Some("taint") {
                    if rule
                        .languages
                        .iter()
                        .any(|l| !matches!(l.as_str(), "javascript" | "typescript"))
                    {
                        return Err(invalid("taint supports JavaScript/TypeScript only"));
                    }
                    let sources = taint_patterns(rule.pattern_sources.as_deref())?;
                    let sinks = taint_patterns(rule.pattern_sinks.as_deref())?;
                    let sanitizers = taint_patterns(rule.pattern_sanitizers.as_deref())?;
                    if sources.is_empty() || sinks.is_empty() {
                        return Err(invalid("taint needs nonempty sources and sinks"));
                    }
                    Ok((None, Some(TaintEngine::new(sources, sinks, sanitizers))))
                } else {
                    let m = fields(
                        rule.pattern.as_deref(),
                        rule.patterns.as_deref(),
                        rule.pattern_either.as_deref(),
                        rule.pattern_regex.as_deref(),
                        rule.pattern_not.as_deref(),
                        rule.pattern_not_inside.as_deref(),
                        rule.pattern_inside.as_deref(),
                        rule.pattern_not_regex.as_deref(),
                    )?;
                    if !m.positive() {
                        return Err(invalid("rule needs a positive selector"));
                    }
                    if rule.languages.iter().any(|l| l == "regex") && m.requires_tree() {
                        return Err(invalid("regex-language rules require regex selectors"));
                    }
                    Ok((Some(m), None))
                }
            })()
            .map_err(|e| invalid(format!("{}: {e}", rule.id)))?;
            compiled.push(CompiledRule {
                rule,
                matcher: result.0,
                taint: result.1,
            });
        }
        Ok(Self { rules: compiled })
    }
    pub fn scan(&self, language: &str, source: &str, path: &Path) -> Vec<Finding> {
        self.scan_checked(language, source, path)
            .unwrap_or_default()
    }
    pub fn scan_checked(&self, language: &str, source: &str, path: &Path) -> Result<Vec<Finding>> {
        let tree = if language.is_empty() || language == "regex" {
            None
        } else {
            let grammar = if path
                .extension()
                .map(|e| e == "tsx" || e == "jsx")
                .unwrap_or(false)
            {
                "tsx"
            } else {
                language
            };
            let tree =
                parse_tree(source.as_bytes(), grammar).map_err(|e| invalid(e.to_string()))?;
            validate_tree(&tree).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
            Some(tree)
        };
        let mut findings = vec![];
        for compiled in &self.rules {
            let rule = &compiled.rule;
            if !rule.languages.iter().any(|l| l == language || l == "regex") {
                continue;
            }
            if let Some(engine) = &compiled.taint {
                findings.extend(
                    engine
                        .analyze_checked(source, path, &rule.id, &rule.message, rule.severity())
                        .map_err(|e| invalid(e.to_string()))?,
                );
                continue;
            }
            let match_tree = if rule.languages.iter().any(|l| l == "regex") {
                None
            } else {
                tree.as_ref()
            };
            let mut spans = compiled.matcher.as_ref().unwrap().spans(source, match_tree);
            spans.sort_by_key(|s| (s.start, s.end));
            spans.dedup();
            for span in spans {
                let line = source[..span.start].bytes().filter(|b| *b == b'\n').count() + 1;
                let column =
                    span.start - source[..span.start].rfind('\n').map(|i| i + 1).unwrap_or(0) + 1;
                let mut f = Finding {
                    id: String::new(),
                    severity: rule.severity(),
                    confidence: 0.7,
                    category: "rule".into(),
                    file: path.into(),
                    line,
                    title: rule.id.clone(),
                    description: rule.message.clone(),
                    execution_path: vec![],
                    affected_components: vec![],
                    evidence: vec![format!("column {column}")],
                    recommendation: String::new(),
                };
                f.stabilize_id();
                findings.push(f);
            }
        }
        let mut seen = HashSet::new();
        findings.retain(|f| seen.insert(f.fingerprint()));
        Ok(findings)
    }
}
fn load_dir(dir: &Path, rules: &mut Vec<Rule>) -> Result<()> {
    let mut paths = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    for p in paths {
        if p.is_dir() {
            load_dir(&p, rules)?;
        } else if p
            .extension()
            .map(|e| e == "yml" || e == "yaml")
            .unwrap_or(false)
        {
            rules.extend(RuleSet::from_yaml(&fs::read_to_string(&p)?)?.rules);
        }
    }
    Ok(())
}
fn taint_patterns(entries: Option<&[PatternEntry]>) -> Result<Vec<String>> {
    let mut out = vec![];
    for e in entries.unwrap_or(&[]) {
        let p = match e {
            PatternEntry::Simple(p) => p.clone(),
            PatternEntry::Complex(value)
                if value.pattern.is_some()
                    && value.extra.is_empty()
                    && value.patterns.is_none()
                    && value.pattern_either.is_none()
                    && value.pattern_not.is_none()
                    && value.pattern_not_inside.is_none()
                    && value.pattern_inside.is_none()
                    && value.pattern_regex.is_none()
                    && value.pattern_not_regex.is_none() =>
            {
                value.pattern.clone().unwrap()
            }
            _ => return Err(invalid("taint entries require simple structural patterns")),
        };
        if p.trim().is_empty() || p.contains('$') || p.contains("...") {
            return Err(invalid(format!("unsupported taint pattern {p}")));
        }
        out.push(p);
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_bundled_rule_has_positive_and_negative_fixtures() {
        let engine = RuleEngine::load_from_embedded_validated().unwrap();
        let fixtures = [
            (
                "rust-unsafe-usage",
                "rust",
                "fn f(){unsafe { work(); }}",
                "fn f(){work();}",
            ),
            (
                "rust-args",
                "rust",
                "fn f(){std::env::args();}",
                "fn f(){args();}",
            ),
            (
                "rust-args-os",
                "rust",
                "fn f(){std::env::args_os();}",
                "fn f(){args_os();}",
            ),
            (
                "rust-current-exe",
                "rust",
                "fn f(){std::env::current_exe();}",
                "fn f(){current_exe();}",
            ),
            (
                "rust-temp-dir",
                "rust",
                "fn f(){std::env::temp_dir();}",
                "fn f(){temp_dir();}",
            ),
            (
                "rust-insecure-hashes",
                "rust",
                "fn f(){md5::Md5::new();}",
                "fn f(){sha2::Sha256::new();}",
            ),
            (
                "rust-reqwest-accept-invalid",
                "rust",
                "fn f(){reqwest::Client::builder().danger_accept_invalid_certs(true);}",
                "fn f(){reqwest::Client::builder().danger_accept_invalid_certs(false);}",
            ),
            (
                "rust-rustls-dangerous",
                "rust",
                "fn f(){client.dangerous().set_certificate_verifier(verifier);}",
                "fn f(){client.set_certificate_verifier(verifier);}",
            ),
            (
                "rust-ssl-verify-none",
                "rust",
                "fn f(){builder.set_verify(openssl::ssl::SSL_VERIFY_NONE);}",
                "fn f(){builder.set_verify(openssl::ssl::SSL_VERIFY_PEER);}",
            ),
            (
                "python-unverified-ssl-context",
                "python",
                "ctx=ssl._create_unverified_context()",
                "ctx=ssl.create_default_context()",
            ),
            (
                "python-insecure-hash-function",
                "python",
                "ctx=hashlib.new('md5', data)",
                "ctx=hashlib.new('md5', data, usedforsecurity=False)",
            ),
            (
                "javascript-detect-insecure-websocket",
                "javascript",
                "const s=new WebSocket('ws://example.com');",
                "const s=new WebSocket('ws://localhost:8080');",
            ),
            (
                "javascript-detect-eval-with-expression",
                "javascript",
                "eval(location.search);",
                "eval('safe');",
            ),
            (
                "javascript-detect-child-process",
                "javascript",
                "function f(cmd){child_process.exec(cmd);}",
                "function f(){child_process.exec('fixed');}",
            ),
            (
                "js-expose-process-env",
                "javascript",
                "const token=process.env.TOKEN;",
                "const token='process.env.TOKEN';",
            ),
            (
                "js-insecure-websocket-server",
                "javascript",
                "const server=new WebSocketServer();",
                "const server=new HttpServer();",
            ),
            (
                "js-unsafe-json-parse",
                "javascript",
                "JSON.parse(req.body);",
                "JSON.parse('{\"safe\":true}');",
            ),
            (
                "taint-user-input-to-json-parse",
                "javascript",
                "JSON.parse(req.body);",
                "JSON.parse('{\"safe\":true}');",
            ),
            (
                "taint-process-env-to-spawn",
                "javascript",
                "spawn(process.env.CMD);",
                "spawn('fixed');",
            ),
        ];
        let ids: HashSet<_> = fixtures.iter().map(|f| f.0).collect();
        assert_eq!(ids.len(), engine.len());
        for (id, lang, positive, negative) in fixtures {
            let path = Path::new(if lang == "rust" {
                "test.rs"
            } else if lang == "python" {
                "test.py"
            } else {
                "test.js"
            });
            assert!(
                engine
                    .scan_checked(lang, positive, path)
                    .unwrap()
                    .iter()
                    .any(|f| f.title == id),
                "positive fixture failed for {id}"
            );
            assert!(
                !engine
                    .scan_checked(lang, negative, path)
                    .unwrap()
                    .iter()
                    .any(|f| f.title == id),
                "negative fixture failed for {id}"
            );
        }
    }
    #[test]
    fn reports_every_occurrence_at_actual_line() {
        let e = RuleEngine::load_from_embedded_validated().unwrap();
        let fs = e
            .scan_checked(
                "rust",
                "fn f(){\nstd::env::args();\nstd::env::args();\n}",
                Path::new("test.rs"),
            )
            .unwrap();
        let lines: Vec<_> = fs
            .iter()
            .filter(|f| f.title == "rust-args")
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, vec![2, 3]);
    }
    #[test]
    fn rejects_unsupported_patterns_and_negative_only_rules() {
        for yaml in ["rules:\n- id: bad\n  message: bad\n  languages: [rust]\n  severity: HIGH\n  pattern: '$CLIENT.call(...)'", "rules:\n- id: bad\n  message: bad\n  languages: [rust]\n  severity: HIGH\n  pattern-not: unsafe"]{
            assert!(RuleEngine::compile(RuleSet::from_yaml(yaml).unwrap().rules).is_err());
        }
    }
    #[test]
    fn exclusion_constraints_apply_to_individual_candidates() {
        let yaml="rules:\n- id: test\n  message: test\n  languages: [regex]\n  severity: HIGH\n  patterns:\n  - pattern-regex: 'ws://[^ ]+'\n  - pattern-not-regex: 'ws://localhost'";
        let e = RuleEngine::compile(RuleSet::from_yaml(yaml).unwrap().rules).unwrap();
        let fs = e
            .scan_checked("regex", "ws://localhost ws://remote", Path::new("test.txt"))
            .unwrap();
        assert_eq!(fs.len(), 1);
    }
}
#[cfg(test)]
mod constraint_regressions {
    use super::*;
    #[test]
    fn inside_and_outside_constraints_use_actual_scopes() {
        let yaml="rules:\n- id: scoped\n  message: scoped\n  languages: [javascript]\n  severity: HIGH\n  pattern: exec(...)\n  pattern-inside: 'function allowed(...) { ... }'";
        let engine = RuleEngine::compile(RuleSet::from_yaml(yaml).unwrap().rules).unwrap();
        let fs = engine
            .scan_checked(
                "javascript",
                "function allowed(){exec(input);} function other(){exec(input);}",
                Path::new("test.js"),
            )
            .unwrap();
        assert_eq!(fs.len(), 1);
        let yaml = yaml.replace("pattern-inside:", "pattern-not-inside:");
        let engine = RuleEngine::compile(RuleSet::from_yaml(&yaml).unwrap().rules).unwrap();
        let fs = engine
            .scan_checked(
                "javascript",
                "function allowed(){exec(input);} function other(){exec(input);}",
                Path::new("test.js"),
            )
            .unwrap();
        assert_eq!(fs.len(), 1);
    }
    #[test]
    fn plain_patterns_do_not_match_comments_or_literals() {
        let engine = RuleEngine::load_from_embedded_validated().unwrap();
        let fs = engine
            .scan_checked(
                "rust",
                r#"fn f(){println!("std::env::args()");} // std::env::args()"#,
                Path::new("test.rs"),
            )
            .unwrap();
        assert!(!fs.iter().any(|f| f.title == "rust-args"));
    }
}
