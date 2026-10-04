use crate::{AstError, Result};
use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MatchSpan {
    pub start: usize,
    pub end: usize,
}
impl MatchSpan {
    pub fn contains(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}
pub fn parse_tree(source: &[u8], language: &str) -> Result<Tree> {
    let mut parser = Parser::new();
    let grammar = match language {
        "python" => tree_sitter_python::language(),
        "rust" => tree_sitter_rust::language(),
        "javascript" | "typescript" => tree_sitter_typescript::language_typescript(),
        "tsx" => tree_sitter_typescript::language_tsx(),
        _ => return Err(AstError::Parse(format!("unsupported language: {language}"))),
    };
    parser
        .set_language(&grammar)
        .map_err(|e| AstError::Parse(e.to_string()))?;
    parser
        .parse(source, None)
        .ok_or_else(|| AstError::Parse("parser returned no tree".into()))
}
pub fn query_pattern(source: &[u8], language: &str, pattern: &str) -> Result<bool> {
    Ok(!pattern_spans(source, language, pattern)?.is_empty())
}
pub fn pattern_spans(source: &[u8], language: &str, pattern: &str) -> Result<Vec<MatchSpan>> {
    let tree = parse_tree(source, language)?;
    let matcher = compile_pattern(pattern)?;
    Ok(match_pattern(
        &tree,
        source,
        &matcher,
        pattern.contains("..."),
    ))
}
pub fn compile_pattern(pattern: &str) -> Result<Regex> {
    if pattern.trim().is_empty() {
        return Err(AstError::Parse("pattern is empty".into()));
    }
    if pattern.contains('$') || pattern.contains("=~/") {
        return Err(AstError::Parse(format!("unsupported pattern: {pattern}")));
    }
    let mut expression = String::new();
    let mut parts = pattern.split("...").peekable();
    while let Some(part) = parts.next() {
        let mut whitespace = false;
        for ch in part.chars() {
            if ch.is_whitespace() {
                whitespace = true;
                continue;
            }
            if whitespace {
                expression.push_str(r"\s*");
                whitespace = false;
            }
            expression.push_str(&regex::escape(&ch.to_string()));
        }
        if whitespace {
            expression.push_str(r"\s*");
        }
        if parts.peek().is_some() {
            expression.push_str("(?s:.*?)");
        }
    }
    if pattern.contains("...") {
        expression.push_str(r"\s*$");
    }
    Regex::new(&expression).map_err(|e| AstError::Parse(e.to_string()))
}
pub fn match_pattern(
    tree: &Tree,
    source: &[u8],
    pattern: &Regex,
    ellipsis: bool,
) -> Vec<MatchSpan> {
    let mut spans = Vec::new();
    visit(tree.root_node(), source, pattern, ellipsis, &mut spans);
    spans.sort_by_key(|s| (s.start, s.end));
    spans.dedup();
    spans
}

pub fn match_context(tree: &Tree, source: &[u8], pattern: &Regex) -> Vec<MatchSpan> {
    let mut out = vec![];
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "function_declaration"
                | "function_definition"
                | "function_item"
                | "method_definition"
                | "class_declaration"
                | "class_definition"
                | "impl_item"
                | "statement_block"
                | "block"
                | "unsafe_block"
                | "if_statement"
                | "call"
                | "call_expression"
        ) {
            if let Ok(text) = n.utf8_text(source) {
                if pattern.find_iter(text).any(|m| {
                    !inside_literal(n, n.start_byte() + m.start(), n.start_byte() + m.end())
                }) {
                    out.push(MatchSpan {
                        start: n.start_byte(),
                        end: n.end_byte(),
                    });
                }
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

pub fn validate_tree(tree: &Tree) -> Result<()> {
    if tree.root_node().has_error() {
        return Err(AstError::Parse("source contains syntax errors".into()));
    }
    let mut stack = vec![(tree.root_node(), 0)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 256 {
            return Err(AstError::Parse("syntax nesting limit exceeded".into()));
        }
        let mut c = node.walk();
        stack.extend(node.named_children(&mut c).map(|n| (n, depth + 1)));
    }
    Ok(())
}
fn visit(n: Node<'_>, source: &[u8], pattern: &Regex, ellipsis: bool, spans: &mut Vec<MatchSpan>) {
    if matches!(
        n.kind(),
        "comment"
            | "line_comment"
            | "block_comment"
            | "string"
            | "string_literal"
            | "raw_string_literal"
    ) {
        return;
    }
    if matches!(
        n.kind(),
        "call"
            | "call_expression"
            | "new_expression"
            | "unsafe_block"
            | "identifier"
            | "member_expression"
            | "attribute"
            | "scoped_identifier"
            | "assignment_expression"
            | "assignment"
    ) {
        if let Ok(text) = n.utf8_text(source) {
            for m in pattern.find_iter(text) {
                if inside_literal(n, n.start_byte() + m.start(), n.start_byte() + m.end()) {
                    continue;
                }
                // Ellipsis call patterns must finish at the end of a call. Receiver prefixes are allowed.
                if !ellipsis || m.end() == text.trim_end().len() {
                    spans.push(MatchSpan {
                        start: n.start_byte() + m.start(),
                        end: n.start_byte() + m.end(),
                    });
                }
            }
        }
    }
    let mut c = n.walk();
    for child in n.named_children(&mut c) {
        visit(child, source, pattern, ellipsis, spans);
    }
}
fn inside_literal(n: Node<'_>, start: usize, end: usize) -> bool {
    if matches!(
        n.kind(),
        "comment"
            | "line_comment"
            | "block_comment"
            | "string"
            | "string_literal"
            | "raw_string_literal"
    ) && n.start_byte() <= start
        && n.end_byte() >= end
    {
        return true;
    }
    let mut c = n.walk();
    let found = n.named_children(&mut c).any(|child| {
        child.start_byte() <= start && child.end_byte() >= end && inside_literal(child, start, end)
    });
    found
}
