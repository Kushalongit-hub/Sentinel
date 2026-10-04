use std::path::PathBuf;
use thiserror::Error;

pub mod ast_query;

pub use ast_query::{
    compile_pattern, match_context, match_pattern, parse_tree, pattern_spans, query_pattern,
    validate_tree, MatchSpan,
};

#[derive(Error, Debug)]
pub enum AstError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Walk error: {0}")]
    Walk(String),
}

impl From<ignore::Error> for AstError {
    fn from(err: ignore::Error) -> Self {
        AstError::Walk(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AstError>;

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub language: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
}

static SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
];

static SKIP_EXTENSIONS: &[&str] = &[
    ".o",
    ".d",
    ".rmeta",
    ".rlib",
    ".bin",
    ".exe",
    ".lock",
    ".a",
    ".dll",
    ".so",
    ".dylib",
    ".timestamp",
];

pub fn walk(path: &str) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    for entry in ignore::WalkBuilder::new(path)
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                || !SKIP_DIRS
                    .iter()
                    .any(|name| entry.file_name() == std::ffi::OsStr::new(name))
        })
        .build()
    {
        let entry = entry?;
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let path_buf = entry.path().to_path_buf();
            if should_skip(&path_buf) {
                continue;
            }
            entries.push(FileEntry {
                path: path_buf.clone(),
                language: detect_language(&path_buf),
            });
        }
    }
    Ok(entries)
}

fn should_skip(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        if SKIP_EXTENSIONS.contains(&(".".to_string() + ext).as_str()) {
            return true;
        }
    }
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            if let Some(s) = name.to_str() {
                if SKIP_DIRS.contains(&s) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn detect_language(path: &std::path::Path) -> Option<String> {
    match path.extension().and_then(|s| s.to_str())? {
        "py" => Some("python".to_string()),
        "ts" => Some("typescript".to_string()),
        "tsx" => Some("typescript".to_string()),
        "js" | "jsx" => Some("javascript".to_string()),
        "rs" => Some("rust".to_string()),
        "go" => Some("go".to_string()),
        _ => None,
    }
}

pub struct SymbolExtractor {
    python_parser: std::cell::RefCell<Option<tree_sitter::Parser>>,
    typescript_parser: std::cell::RefCell<Option<tree_sitter::Parser>>,
    rust_parser: std::cell::RefCell<Option<tree_sitter::Parser>>,
    tsx_parser: std::cell::RefCell<Option<tree_sitter::Parser>>,
}

impl SymbolExtractor {
    pub fn new() -> Self {
        Self {
            python_parser: std::cell::RefCell::new(init_parser(&tree_sitter_python::language())),
            typescript_parser: std::cell::RefCell::new(init_parser(
                &tree_sitter_typescript::language_typescript(),
            )),
            rust_parser: std::cell::RefCell::new(init_parser(&tree_sitter_rust::language())),
            tsx_parser: std::cell::RefCell::new(init_parser(
                &tree_sitter_typescript::language_tsx(),
            )),
        }
    }

    pub fn extract(&self, path: &std::path::Path, source: &[u8]) -> Result<Vec<Symbol>> {
        let language = detect_language(path)
            .ok_or_else(|| AstError::Parse("unsupported language".to_string()))?;
        let parser = if path
            .extension()
            .map(|e| e == "tsx" || e == "jsx")
            .unwrap_or(false)
        {
            &self.tsx_parser
        } else {
            match language.as_str() {
                "python" => &self.python_parser,
                "typescript" | "javascript" => &self.typescript_parser,
                "rust" => &self.rust_parser,
                _ => return Ok(Vec::new()),
            }
        };
        let mut parser = parser.borrow_mut();
        let parser = match parser.as_mut() {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AstError::Parse("parse failed".to_string()))?;
        validate_tree(&tree)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        match language.as_str() {
            "python" => extract_python_symbols(&root, source, &mut symbols),
            "typescript" | "javascript" => extract_typescript_symbols(&root, source, &mut symbols),
            "rust" => extract_rust_symbols(&root, source, &mut symbols),
            _ => {}
        }
        Ok(symbols)
    }
}

fn extract_python_symbols(node: &tree_sitter::Node, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" | "async_function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "function".to_string(),
                        line,
                    });
                }
            }
            "class_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "class".to_string(),
                        line,
                    });
                }
            }
            _ => {}
        }
        extract_python_symbols(&child, source, symbols);
    }
}

fn extract_typescript_symbols(node: &tree_sitter::Node, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" | "method_definition" | "arrow_function" => {
                if let Some(name_node) = child.child_by_field_name("name").or_else(|| {
                    child
                        .parent()
                        .filter(|p| p.kind() == "variable_declarator")
                        .and_then(|p| p.child_by_field_name("name"))
                }) {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "function".to_string(),
                        line,
                    });
                }
            }
            "class_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "class".to_string(),
                        line,
                    });
                }
            }
            "interface_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "interface".to_string(),
                        line,
                    });
                }
            }
            _ => {}
        }
        extract_typescript_symbols(&child, source, symbols);
    }
}

fn extract_rust_symbols(node: &tree_sitter::Node, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "function".to_string(),
                        line,
                    });
                }
            }
            "struct_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "struct".to_string(),
                        line,
                    });
                }
            }
            "impl_item" => {
                if let Some(name_node) = child.child_by_field_name("type") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "impl".to_string(),
                        line,
                    });
                }
            }
            "trait_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "trait".to_string(),
                        line,
                    });
                }
            }
            "enum_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "enum".to_string(),
                        line,
                    });
                }
            }
            "mod_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let text = node_text(source, &name_node);
                    let line = name_node.start_position().row + 1;
                    symbols.push(Symbol {
                        name: text,
                        kind: "module".to_string(),
                        line,
                    });
                }
            }
            _ => {}
        }
        extract_rust_symbols(&child, source, symbols);
    }
}

fn node_text(source: &[u8], node: &tree_sitter::Node) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    String::from_utf8_lossy(&source[start..end]).to_string()
}

fn init_parser(language: &tree_sitter::Language) -> Option<tree_sitter::Parser> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).ok()?;
    Some(parser)
}

impl Default for SymbolExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_pattern_unsafe() {
        let source = br#"unsafe {
    let ptr = 0x1234 as *const i32;
    println!("{}", *ptr);
}
"#;
        let result = query_pattern(source, "rust", "unsafe { ... }");
        assert!(result.is_ok());
        assert!(result.unwrap(), "unsafe block should match");
    }

    #[test]
    fn test_query_pattern_call() {
        let source = br#"md5::Md5::new();
"#;
        let result = query_pattern(source, "rust", "md5::Md5::new(...)");
        assert!(result.is_ok());
        assert!(result.unwrap(), "call expression should match");
    }
}
#[cfg(test)]
mod symbol_regressions {
    use super::*;
    fn names(path: &str, source: &str) -> Vec<String> {
        SymbolExtractor::new()
            .extract(std::path::Path::new(path), source.as_bytes())
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect()
    }
    #[test]
    fn indexes_class_members_and_nested_functions() {
        let found = names(
            "test.py",
            "class Example:\n    def method(self):\n        def nested():\n            pass\n",
        );
        for name in ["Example", "method", "nested"] {
            assert!(found.iter().any(|n| n == name));
        }
    }
    #[test]
    fn indexes_impl_methods_and_module_contents() {
        let found = names(
            "test.rs",
            "mod m { struct Example; impl Example { fn method(){fn nested(){}} } }",
        );
        for name in ["m", "Example", "method", "nested"] {
            assert!(found.iter().any(|n| n == name));
        }
    }
    #[test]
    fn names_arrow_functions_and_handles_tsx() {
        let found = names("test.tsx", "const Component = () => <div />;");
        assert!(found.iter().any(|n| n == "Component"));
    }
}
