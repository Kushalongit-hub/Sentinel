use crate::{AstError, Result};

pub fn query_pattern(source: &[u8], language: &str, pattern: &str) -> Result<bool> {
    if !pattern.contains("...") {
        return Ok(false);
    }

    let parts: Vec<&str> = pattern.split("...").collect();
    if parts.is_empty() {
        return Ok(false);
    }

    let node_kinds = infer_node_kinds(language, pattern);

    match language {
        "python" => PYTHON_PARSER.with(|parser| {
            let mut binding = parser.borrow_mut();
            let parser = match binding.as_mut() {
                Some(p) => p,
                None => return Err(AstError::Parse("parser not initialized".to_string())),
            };
            let tree = match parser.parse(source, None) {
                Some(t) => t,
                None => return Err(AstError::Parse("parse failed".to_string())),
            };
            let root = tree.root_node();
            search_nodes(source, &root, node_kinds, &parts)
        }),
        "typescript" | "javascript" => TYPESCRIPT_PARSER.with(|parser| {
            let mut binding = parser.borrow_mut();
            let parser = match binding.as_mut() {
                Some(p) => p,
                None => return Err(AstError::Parse("parser not initialized".to_string())),
            };
            let tree = match parser.parse(source, None) {
                Some(t) => t,
                None => return Err(AstError::Parse("parse failed".to_string())),
            };
            let root = tree.root_node();
            search_nodes(source, &root, node_kinds, &parts)
        }),
        "rust" => RUST_PARSER.with(|parser| {
            let mut binding = parser.borrow_mut();
            let parser = match binding.as_mut() {
                Some(p) => p,
                None => return Err(AstError::Parse("parser not initialized".to_string())),
            };
            let tree = match parser.parse(source, None) {
                Some(t) => t,
                None => return Err(AstError::Parse("parse failed".to_string())),
            };
            let root = tree.root_node();
            search_nodes(source, &root, node_kinds, &parts)
        }),
        _ => Ok(false),
    }
}

fn search_nodes(
    source: &[u8],
    root: &tree_sitter::Node,
    node_kinds: &[&str],
    parts: &[&str],
) -> Result<bool> {
    let mut found = 0;
    if search_nodes_recursive(source, root, node_kinds, parts, &mut found) {
        return Ok(true);
    }
    Ok(false)
}

fn search_nodes_recursive(
    source: &[u8],
    node: &tree_sitter::Node,
    node_kinds: &[&str],
    parts: &[&str],
    found: &mut i32,
) -> bool {
    if node_kinds.contains(&node.kind()) {
        *found += 1;
        let text = node_text(source, node);
        if matches_ellipsis_pattern(&text, parts) {
            return true;
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if search_nodes_recursive(source, &child, node_kinds, parts, found) {
            return true;
        }
    }
    false
}

fn matches_ellipsis_pattern(text: &str, parts: &[&str]) -> bool {
    if parts.is_empty() {
        return false;
    }
    let prefix = parts[0].trim();
    let suffix = parts.last().map(|s| s.trim()).unwrap_or("");

    if parts.len() == 1 {
        return text.contains(prefix);
    }

    let starts_with = if prefix.is_empty() {
        true
    } else {
        text.trim_start().starts_with(prefix)
    };

    let ends_with = if suffix.is_empty() {
        true
    } else {
        text.trim_end().ends_with(suffix)
    };

    if !starts_with || !ends_with {
        return false;
    }

    if parts.len() > 2 {
        for part in &parts[1..parts.len() - 1] {
            let part = part.trim();
            if !part.is_empty() && !text.contains(part) {
                return false;
            }
        }
    }

    true
}

fn infer_node_kinds(language: &str, pattern: &str) -> &'static [&'static str] {
    match language {
        "rust" => {
            if pattern.starts_with("unsafe") {
                &["unsafe_block"]
            } else if pattern.contains("::") && pattern.contains("(") {
                &["call_expression", "scoped_identifier"]
            } else {
                &["call_expression", "field_expression", "identifier"]
            }
        }
        "python" => {
            if pattern.contains("(") {
                &["call"]
            } else {
                &["identifier", "attribute"]
            }
        }
        "typescript" | "javascript" => {
            if pattern.contains("(") {
                &["call_expression", "member_expression"]
            } else {
                &["identifier", "member_expression"]
            }
        }
        _ => &[],
    }
}

fn node_text(source: &[u8], node: &tree_sitter::Node) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    String::from_utf8_lossy(&source[start..end]).to_string()
}

thread_local! {
    static PYTHON_PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> = std::cell::RefCell::new(init_parser(&tree_sitter_python::language()));
    static TYPESCRIPT_PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> = std::cell::RefCell::new(init_parser(&tree_sitter_typescript::language_typescript()));
    static RUST_PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> = std::cell::RefCell::new(init_parser(&tree_sitter_rust::language()));
}

fn init_parser(language: &tree_sitter::Language) -> Option<tree_sitter::Parser> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).ok()?;
    Some(parser)
}
