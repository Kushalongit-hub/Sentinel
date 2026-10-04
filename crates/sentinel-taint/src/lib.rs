use sentinel_core::{Finding, Severity};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tree_sitter::{Node, Parser};

#[derive(Error, Debug)]
pub enum TaintError {
    #[error("parse error: {0}")]
    Parse(String),
}
pub type TaintResult<T> = Result<T, TaintError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintLevel {
    Clean,
    Tainted,
}
#[derive(Debug, Clone, Default)]
pub struct TaintContext {
    variables: HashMap<String, TaintLevel>,
}
impl TaintContext {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, name: String, level: TaintLevel) {
        self.variables.insert(name, level);
    }
    pub fn get(&self, name: &str) -> TaintLevel {
        self.variables
            .get(name)
            .copied()
            .unwrap_or(TaintLevel::Clean)
    }
    pub fn is_tainted(&self, name: &str) -> bool {
        self.get(name) == TaintLevel::Tainted
    }
}
#[derive(Clone, Default, PartialEq, Eq)]
struct Environment {
    scopes: Vec<HashMap<String, bool>>,
}
impl Environment {
    fn lookup(&self, name: &str) -> bool {
        self.scopes
            .iter()
            .rev()
            .find_map(|s| s.get(name).copied())
            .unwrap_or(false)
    }
    fn declare(&mut self, name: String, value: bool) {
        self.scopes.last_mut().unwrap().insert(name, value);
    }
    fn assign(&mut self, name: String, value: bool) {
        for scope in self.scopes.iter_mut().rev() {
            if let Some(binding) = scope.get_mut(&name) {
                *binding = value;
                return;
            }
        }
        self.declare(name, value);
    }
    fn merge(&mut self, other: &Self) {
        for (scope, branch) in self.scopes.iter_mut().zip(&other.scopes) {
            for (key, value) in scope.iter_mut() {
                *value |= branch.get(key).copied().unwrap_or(false);
            }
        }
    }
}
#[derive(Debug)]
pub struct TaintEngine {
    sources: Vec<String>,
    sinks: Vec<String>,
    sanitizers: Vec<String>,
}
impl TaintEngine {
    pub fn new(sources: Vec<String>, sinks: Vec<String>, sanitizers: Vec<String>) -> Self {
        Self {
            sources,
            sinks,
            sanitizers,
        }
    }
    pub fn analyze_file(
        &self,
        source: &str,
        path: &std::path::Path,
        id: &str,
        message: &str,
        severity: Severity,
    ) -> Vec<Finding> {
        self.analyze_checked(source, path, id, message, severity)
            .unwrap_or_default()
    }
    pub fn analyze_checked(
        &self,
        source: &str,
        path: &std::path::Path,
        id: &str,
        message: &str,
        severity: Severity,
    ) -> TaintResult<Vec<Finding>> {
        let mut parser = Parser::new();
        let grammar = if path
            .extension()
            .map(|e| e == "tsx" || e == "jsx")
            .unwrap_or(false)
        {
            tree_sitter_typescript::language_tsx()
        } else {
            tree_sitter_typescript::language_typescript()
        };
        parser
            .set_language(&grammar)
            .map_err(|e| TaintError::Parse(e.to_string()))?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| TaintError::Parse("parser returned no tree".into()))?;
        sentinel_ast::validate_tree(&tree)
            .map_err(|e| TaintError::Parse(format!("{}: {e}", path.display())))?;
        let mut env = Environment {
            scopes: vec![HashMap::new()],
        };
        let mut positions = HashSet::new();
        self.visit(tree.root_node(), source, &mut env, &mut positions);
        let mut positions: Vec<_> = positions.into_iter().collect();
        positions.sort_unstable();
        Ok(positions
            .into_iter()
            .map(|(line, column)| {
                let mut f = Finding {
                    id: String::new(),
                    severity,
                    confidence: 0.6,
                    category: "taint".into(),
                    file: path.into(),
                    line,
                    title: id.into(),
                    description: message.into(),
                    execution_path: vec![],
                    affected_components: vec![],
                    evidence: vec![format!("column {column}")],
                    recommendation: String::new(),
                };
                f.stabilize_id();
                f
            })
            .collect())
    }
    fn text<'a>(&self, n: Node<'_>, s: &'a str) -> &'a str {
        &s[n.byte_range()]
    }
    fn callee_matches(&self, text: &str, patterns: &[String]) -> bool {
        let text = text.split_whitespace().collect::<String>();
        patterns.iter().any(|p| {
            let p = p.trim().trim_end_matches('(').trim_end_matches("(...)");
            text == p || text.ends_with(&format!(".{p}"))
        })
    }
    fn evaluate(&self, n: Node<'_>, s: &str, env: &Environment) -> bool {
        if matches!(
            n.kind(),
            "string" | "string_fragment" | "comment" | "number" | "true" | "false" | "null"
        ) {
            return false;
        }
        let text = self.text(n, s);
        if matches!(
            n.kind(),
            "identifier" | "member_expression" | "subscript_expression" | "call_expression"
        ) && self
            .sources
            .iter()
            .filter(|p| p.as_str() != "@parameter")
            .any(|p| text == p || text.starts_with(&format!("{p}.")))
        {
            return true;
        }
        if n.kind() == "identifier" {
            return env.lookup(text);
        }
        if n.kind() == "call_expression" || n.kind() == "new_expression" {
            if let Some(callee) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("constructor"))
            {
                if self.callee_matches(self.text(callee, s), &self.sanitizers) {
                    return false;
                }
                if self.callee_matches(self.text(callee, s), &self.sources) {
                    return true;
                }
            }
            return n
                .child_by_field_name("arguments")
                .map(|a| self.evaluate(a, s, env))
                .unwrap_or(false);
        }
        let mut c = n.walk();
        let tainted = n
            .named_children(&mut c)
            .any(|child| self.evaluate(child, s, env));
        tainted
    }
    fn visit(
        &self,
        n: Node<'_>,
        s: &str,
        env: &mut Environment,
        hits: &mut HashSet<(usize, usize)>,
    ) {
        match n.kind() {
            "comment" | "string" => {}
            "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition" => {
                let mut local = env.clone();
                local.scopes.push(HashMap::new());
                if let Some(params) = n
                    .child_by_field_name("parameters")
                    .or_else(|| n.child_by_field_name("parameter"))
                {
                    let tainted = self.sources.iter().any(|p| p == "@parameter");
                    declare_parameters(params, s, &mut local, tainted);
                }
                if let Some(body) = n.child_by_field_name("body") {
                    self.visit(body, s, &mut local, hits);
                }
            }
            "statement_block" => {
                env.scopes.push(HashMap::new());
                let mut c = n.walk();
                for child in n.named_children(&mut c) {
                    self.visit(child, s, env, hits);
                }
                env.scopes.pop();
            }
            "variable_declarator" => {
                if let Some(value) = n.child_by_field_name("value") {
                    self.visit(value, s, env, hits);
                    let level = self.evaluate(value, s, env);
                    if let Some(name) = n.child_by_field_name("name") {
                        declare_parameters(name, s, env, level);
                    }
                } else if let Some(name) = n.child_by_field_name("name") {
                    declare_parameters(name, s, env, false);
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                if let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    self.visit(right, s, env, hits);
                    let mut level = self.evaluate(right, s, env);
                    if n.kind() == "augmented_assignment_expression" {
                        level |= self.evaluate(left, s, env);
                    }
                    if left.kind() == "identifier" {
                        env.assign(self.text(left, s).into(), level);
                    } else if let Some(object) = left.child_by_field_name("object") {
                        if object.kind() == "identifier" {
                            let name = self.text(object, s);
                            env.assign(name.into(), level || env.lookup(name));
                        }
                    }
                }
            }
            "if_statement" | "ternary_expression" => {
                if let Some(condition) = n.child_by_field_name("condition") {
                    self.visit(condition, s, env, hits);
                }
                let base = env.clone();
                let mut yes = base.clone();
                let mut no = base.clone();
                if let Some(branch) = n.child_by_field_name("consequence") {
                    self.visit(branch, s, &mut yes, hits);
                }
                if let Some(branch) = n.child_by_field_name("alternative") {
                    self.visit(branch, s, &mut no, hits);
                }
                *env = yes;
                env.merge(&no);
            }
            "while_statement" | "do_statement" | "for_statement" | "for_in_statement" => {
                env.scopes.push(HashMap::new());
                if let Some(init) = n.child_by_field_name("initializer") {
                    self.visit(init, s, env, hits);
                }
                // Finite Boolean lattice: each iteration adds tainted bindings; iterate to a fixed point.
                loop {
                    let before = env.clone();
                    let mut iteration = before.clone();
                    let mut c = n.walk();
                    for child in n.named_children(&mut c) {
                        self.visit(child, s, &mut iteration, hits);
                    }
                    env.merge(&iteration);
                    if *env == before {
                        break;
                    }
                }
                env.scopes.pop();
            }
            "try_statement" | "switch_statement" => {
                let base = env.clone();
                let mut c = n.walk();
                for child in n.named_children(&mut c) {
                    let mut branch = base.clone();
                    self.visit(child, s, &mut branch, hits);
                    env.merge(&branch);
                }
            }
            "call_expression" | "new_expression" => {
                let mut c = n.walk();
                for child in n.named_children(&mut c) {
                    self.visit(child, s, env, hits);
                }
                if let Some(callee) = n
                    .child_by_field_name("function")
                    .or_else(|| n.child_by_field_name("constructor"))
                {
                    if self.callee_matches(self.text(callee, s), &self.sinks)
                        && n.child_by_field_name("arguments")
                            .map(|a| self.evaluate(a, s, env))
                            .unwrap_or(false)
                    {
                        let pos = n.start_position();
                        hits.insert((pos.row + 1, pos.column + 1));
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                for child in n.named_children(&mut c) {
                    self.visit(child, s, env, hits);
                }
            }
        }
    }
}
fn declare_parameters(n: Node<'_>, s: &str, env: &mut Environment, level: bool) {
    if n.kind() == "identifier" {
        env.declare(s[n.byte_range()].into(), level);
        return;
    }
    if let Some(pattern) = n.child_by_field_name("pattern") {
        declare_parameters(pattern, s, env, level);
        return;
    }
    let mut c = n.walk();
    for child in n.named_children(&mut c) {
        if !child.kind().contains("type") {
            declare_parameters(child, s, env, level);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hits(code: &str, sanitizers: Vec<String>) -> usize {
        TaintEngine::new(vec!["user_input".into()], vec!["exec(".into()], sanitizers)
            .analyze_checked(
                code,
                std::path::Path::new("test.js"),
                "test",
                "test",
                Severity::High,
            )
            .unwrap()
            .len()
    }
    #[test]
    fn tracks_assignment_rhs() {
        assert_eq!(
            hits(
                "let data=user_input; let result; result=exec(data);",
                vec![]
            ),
            1
        );
    }
    #[test]
    fn merges_conditional_state() {
        assert_eq!(
            hits(
                "let data=user_input; if(flag){data='safe';} exec(data);",
                vec![]
            ),
            1
        );
    }
    #[test]
    fn respects_shadowing() {
        assert_eq!(
            hits(
                "let data=user_input; {let data='safe';} exec(data);",
                vec![]
            ),
            1
        );
    }
    #[test]
    fn merges_loops() {
        assert_eq!(
            hits(
                "let data='safe'; while(flag){data=user_input;} exec(data);",
                vec![]
            ),
            1
        );
    }
    #[test]
    fn reads_captured_bindings() {
        assert_eq!(
            hits("let data=user_input; function f(){exec(data);}", vec![]),
            1
        );
    }
    #[test]
    fn sanitizes_only_transformed_values() {
        assert_eq!(
            hits("exec(escapeHtml(user_input));", vec!["escapeHtml".into()]),
            0
        );
        assert_eq!(
            hits(
                "let data=user_input+escapeHtml('safe'); exec(data);",
                vec!["escapeHtml".into()]
            ),
            1
        );
    }
    #[test]
    fn ignores_source_text_in_literals() {
        assert_eq!(hits("exec('user_input');", vec![]), 0);
    }
}
pub mod interprocedural;
