use std::collections::HashMap;
use thiserror::Error;
use sentinel_core::{Finding, Severity};
use tree_sitter::{Parser, Node};

#[derive(Error, Debug)]
pub enum TaintError {
    #[error("parse error: {0}")]
    Parse(String),
}

pub type TaintResult<T> = Result<T, TaintError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaintLevel {
    Clean,
    Tainted,
}

#[derive(Debug, Clone)]
pub struct TaintContext {
    variables: HashMap<String, TaintLevel>,
}

impl TaintContext {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn set(&mut self, name: String, level: TaintLevel) {
        self.variables.insert(name, level);
    }

    pub fn get(&self, name: &str) -> TaintLevel {
        self.variables.get(name).copied().unwrap_or(TaintLevel::Clean)
    }

    pub fn is_tainted(&self, name: &str) -> bool {
        self.get(name) == TaintLevel::Tainted
    }
}

impl Default for TaintContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub rule_id: String,
    pub message: String,
    pub line: usize,
    pub severity: Severity,
    pub file_path: std::path::PathBuf,
}

#[derive(Debug)]
struct TaintRuleContext<'a> {
    rule_id: &'a str,
    message: &'a str,
    severity: Severity,
    file_path: &'a std::path::Path,
}

impl TaintFinding {
    pub fn into_finding(self) -> Finding {
        Finding {
            id: format!("{}-{}", self.rule_id, uuid::Uuid::new_v4().simple()),
            severity: self.severity,
            confidence: 0.6,
            category: "taint".to_string(),
            file: self.file_path,
            line: self.line,
            title: self.rule_id,
            description: self.message,
            execution_path: Vec::new(),
            affected_components: Vec::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct TaintEngine {
    source_patterns: Vec<String>,
    sink_patterns: Vec<String>,
    sanitizer_patterns: Vec<String>,
}

impl TaintEngine {
    pub fn new(sources: Vec<String>, sinks: Vec<String>, sanitizers: Vec<String>) -> Self {
        Self {
            source_patterns: sources,
            sink_patterns: sinks,
            sanitizer_patterns: sanitizers,
        }
    }

    pub fn analyze_file(&self, source: &str, file_path: &std::path::Path, rule_id: &str, message: &str, severity: Severity) -> Vec<Finding> {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_typescript::language_typescript()).ok();
        let tree = match parser.parse(source.as_bytes(), None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let root = tree.root_node();

        let mut findings = Vec::new();
        let mut contexts: Vec<TaintContext> = Vec::new();
        contexts.push(TaintContext::new());

        walk_with_scope(
            source,
            &root,
            &mut contexts,
            self,
            &mut findings,
            &TaintRuleContext {
                rule_id,
                message,
                severity,
                file_path,
            },
        );

        findings.into_iter().map(|f| f.into_finding()).collect()
    }
}

fn walk_with_scope(
    source: &str,
    node: &Node,
    contexts: &mut Vec<TaintContext>,
    engine: &TaintEngine,
    findings: &mut Vec<TaintFinding>,
    rule: &TaintRuleContext,
) {
    let sources = &engine.source_patterns;
    let sinks = &engine.sink_patterns;
    let sanitizers = &engine.sanitizer_patterns;
    let rule_id = rule.rule_id;
    let message = rule.message;
    let severity = rule.severity;
    let file_path = rule.file_path;

    match node.kind() {
        "function_declaration" | "function_expression" | "arrow_function" | "method_definition" => {
            let mut ctx = TaintContext::new();

            if let Some(params) = node.child_by_field_name("parameters") {
                collect_identifiers(source.as_bytes(), &params, &mut |name| {
                    ctx.variables.insert(name, TaintLevel::Clean);
                });
            }

            contexts.push(ctx);

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_with_scope(source, &child, contexts, engine, findings, rule);
            }

            contexts.pop();
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let (Some(name_node), Some(value_node)) = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("value"),
                    ) {
                        if name_node.kind() == "identifier" {
                            let name = node_text(source.as_bytes(), &name_node);
                            let tainted = evaluate_taint(source, &value_node, contexts.last(), sources);
                            let level = if tainted {
                                if contains_sanitizer(source, &value_node, sanitizers) {
                                    TaintLevel::Clean
                                } else {
                                    TaintLevel::Tainted
                                }
                            } else {
                                TaintLevel::Clean
                            };
                            if let Some(ctx) = contexts.last_mut() {
                                ctx.set(name, level);
                            }
                        }
                    }
                }
                walk_with_scope(source, &child, contexts, engine, findings, rule);
            }
        }
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let name = node_text(source.as_bytes(), &left);
                    let tainted = evaluate_taint(source, &right, contexts.last(), sources);
                    let level = if tainted {
                        if contains_sanitizer(source, &right, sanitizers) {
                            TaintLevel::Clean
                        } else {
                            TaintLevel::Tainted
                        }
                    } else {
                        TaintLevel::Clean
                    };
                    if let Some(ctx) = contexts.last_mut() {
                        ctx.set(name, level);
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_with_scope(source, &child, contexts, engine, findings, rule);
            }
        }
        "call_expression" => {
            if let Some(_func_node) = node.child_by_field_name("function") {
                let call_text = node_text(source.as_bytes(), node);
                if sinks.iter().any(|s| call_text.contains(&**s)) {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        if has_tainted_identifier(source, &args_node, contexts.last(), sources) {
                            let line = node.start_position().row + 1;
                            findings.push(TaintFinding {
                                rule_id: rule_id.to_string(),
                                message: message.to_string(),
                                line,
                                severity,
                                file_path: file_path.to_path_buf(),
                            });
                        }
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_with_scope(source, &child, contexts, engine, findings, rule);
            }
        }
        "if_statement" | "for_in_statement" | "for_of_statement" | "while_statement" | "do_statement" | "try_statement" | "statement_block" => {
            if let Some(block) = node.child_by_field_name("body") {
                if contexts.last().map(|ctx| ctx.variables.len()) > Some(0) {
                    contexts.push(contexts.last().cloned().unwrap_or_default());
                } else {
                    contexts.push(TaintContext::new());
                }
                walk_with_scope(source, &block, contexts, engine, findings, rule);
                contexts.pop();
            } else {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    walk_with_scope(source, &child, contexts, engine, findings, rule);
                }
            }
        }
        "catch_clause" | "finally_clause" => {
            if let Some(body) = node.child_by_field_name("body") {
                contexts.push(contexts.last().cloned().unwrap_or_default());
                walk_with_scope(source, &body, contexts, engine, findings, rule);
                contexts.pop();
            } else {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    walk_with_scope(source, &child, contexts, engine, findings, rule);
                }
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_with_scope(source, &child, contexts, engine, findings, rule);
            }
        }
    }
}

fn evaluate_taint(source: &str, node: &Node, ctx: Option<&TaintContext>, sources: &[String]) -> bool {
    let text = node_text(source.as_bytes(), node);
    if sources.iter().any(|s| text.contains(s)) {
        return true;
    }

    if let Some(context) = ctx {
        if has_tainted_identifier(source, node, Some(context), sources) {
            return true;
        }
    }

    false
}

fn contains_sanitizer(source: &str, node: &Node, sanitizers: &[String]) -> bool {
    let text = node_text(source.as_bytes(), node);
    sanitizers.iter().any(|s| text.contains(s))
}

fn has_tainted_identifier(source: &str, node: &Node, ctx: Option<&TaintContext>, sources: &[String]) -> bool {
    if sources.iter().any(|s| node_text(source.as_bytes(), node).contains(s)) {
        return true;
    }

    match node.kind() {
        "identifier" => {
            if let Ok(name) = node.utf8_text(source.as_bytes()) {
                if let Some(context) = ctx {
                    return context.is_tainted(name);
                }
            }
            false
        }
        "member_expression" => {
            if let Some(object) = node.child_by_field_name("object") {
                if object.kind() == "identifier" {
                    if let Ok(name) = object.utf8_text(source.as_bytes()) {
                        if let Some(context) = ctx {
                            if context.is_tainted(name) {
                                return true;
                            }
                        }
                    }
                }
                if has_tainted_identifier(source, &object, ctx, sources) {
                    return true;
                }
            }
            if let Some(property) = node.child_by_field_name("property") {
                if has_tainted_identifier(source, &property, ctx, sources) {
                    return true;
                }
            }
            false
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if has_tainted_identifier(source, &child, ctx, sources) {
                    return true;
                }
            }
            false
        }
    }
}

fn collect_identifiers(source: &[u8], node: &Node, f: &mut impl FnMut(String)) {
    match node.kind() {
        "identifier" => {
            if let Ok(name) = std::str::from_utf8(&source[node.start_byte()..node.end_byte()]) {
                f(name.to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_identifiers(source, &child, f);
            }
        }
    }
}

fn node_text(source: &[u8], node: &Node) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    String::from_utf8_lossy(&source[start..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_taint_propagation() {
        let engine = TaintEngine::new(
            vec!["user_input".to_string()],
            vec!["exec(".to_string()],
            vec![],
        );

        let source = r#"function test() {
    let data = user_input;
    exec(data);
}
"#;
        let findings = engine.analyze_file(source, std::path::Path::new("test.js"), "test-taint", "taint test", Severity::High);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].line >= 1);
    }

    #[test]
    fn test_sanitizer_clears_taint() {
        let engine = TaintEngine::new(
            vec!["user_input".to_string()],
            vec!["exec(".to_string()],
            vec!["escapeHtml".to_string()],
        );

        let source = r#"
function test() {
    let data = escapeHtml(user_input);
    exec(data);
}
"#;
        let findings = engine.analyze_file(source, std::path::Path::new("test.js"), "test-sanitizer", "sanitizer test", Severity::High);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_no_false_positive() {
        let engine = TaintEngine::new(
            vec!["user_input".to_string()],
            vec!["exec(".to_string()],
            vec![],
        );

        let source = r#"
function test() {
    let data = "safe";
    exec(data);
}
"#;
        let findings = engine.analyze_file(source, std::path::Path::new("test.js"), "test-safe", "safe test", Severity::High);
        assert_eq!(findings.len(), 0);
    }
}
