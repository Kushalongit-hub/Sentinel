//! AST-derived repository definitions and a compact security flow representation.
use sentinel_core::security::*;
use std::{collections::BTreeMap, path::Path};
use tree_sitter::Node;

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
fn snippet(node: Node<'_>, source: &str) -> String {
    text(node, source)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}
fn named(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}
fn source_name(value: &str) -> bool {
    let value = value.split_whitespace().collect::<String>();
    [
        "req.body",
        "req.query",
        "req.params",
        "request.args",
        "request.form",
        "request.json",
        "request.GET",
        "request.POST",
        "request.query",
        "request.body",
        "request.query_params",
        "location.hash",
        "location.search",
        "window.location.hash",
        "window.location.search",
    ]
    .iter()
    .any(|s| {
        value == *s || value.starts_with(&format!("{s}.")) || value.starts_with(&format!("{s}["))
    })
}
fn expression(node: Node<'_>, source: &str) -> FlowExpr {
    let raw = text(node, source);
    let line = node.start_position().row + 1;
    if !matches!(
        node.kind(),
        "string" | "string_literal" | "comment" | "string_fragment"
    ) && source_name(raw)
    {
        return FlowExpr::Source {
            name: raw.chars().take(100).collect(),
            line,
        };
    }
    match node.kind() {
        "identifier" | "field_identifier" | "scoped_identifier" | "member_expression"
        | "attribute" | "field_expression" => FlowExpr::Variable {
            name: raw.split_whitespace().collect(),
        },
        "call" | "call_expression" | "new_expression" => {
            let callee = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("constructor"));
            let name = callee
                .map(|n| text(n, source).split_whitespace().collect::<String>())
                .unwrap_or_default();
            if ["input", "request.get_json", "sys.stdin.read"].contains(&name.as_str())
                || source_name(&name)
            {
                return FlowExpr::Source { name, line };
            }
            let args = node
                .child_by_field_name("arguments")
                .map(named)
                .unwrap_or_default();
            let shell = args.iter().any(|n| {
                text(*n, source).split_whitespace().collect::<String>() == "shell=True"
                    || text(*n, source)
                        .split_whitespace()
                        .collect::<String>()
                        .contains("shell:true")
            });
            FlowExpr::Call {
                name,
                args: args.into_iter().map(|n| expression(n, source)).collect(),
                line,
                snippet: snippet(node, source),
                shell,
            }
        }
        "string" | "template_string" => {
            let values = named(node)
                .into_iter()
                .filter(|n| matches!(n.kind(), "interpolation" | "template_substitution"))
                .flat_map(named)
                .map(|n| expression(n, source))
                .collect();
            FlowExpr::Join { values }
        }
        "arrow_function"
        | "function_expression"
        | "function_definition"
        | "function_declaration"
        | "function_item"
        | "string_literal"
        | "string_fragment"
        | "integer"
        | "float"
        | "number"
        | "true"
        | "false"
        | "none"
        | "null"
        | "comment" => FlowExpr::Literal,
        _ => FlowExpr::Join {
            values: named(node)
                .into_iter()
                .map(|n| expression(n, source))
                .collect(),
        },
    }
}
fn statements(node: Node<'_>, source: &str) -> Vec<FlowStmt> {
    let line = node.start_position().row + 1;
    match node.kind() {
        "function_definition"
        | "function_declaration"
        | "function_item"
        | "function_expression"
        | "arrow_function"
        | "class_definition"
        | "class_declaration"
        | "method_definition"
        | "impl_item"
        | "mod_item"
        | "struct_item"
        | "decorated_definition" => vec![],
        "block" | "statement_block" => vec![FlowStmt::Scope {
            body: named(node)
                .into_iter()
                .flat_map(|n| statements(n, source))
                .collect(),
        }],
        "program" | "module" => named(node)
            .into_iter()
            .flat_map(|n| statements(n, source))
            .collect(),
        "lexical_declaration" | "variable_declaration" => named(node)
            .into_iter()
            .flat_map(|n| statements(n, source))
            .collect(),
        "expression_statement" => named(node)
            .into_iter()
            .flat_map(|n| statements(n, source))
            .collect(),
        "assignment"
        | "assignment_expression"
        | "augmented_assignment"
        | "augmented_assignment_expression"
        | "variable_declarator"
        | "let_declaration" => {
            let left = node
                .child_by_field_name("left")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.child_by_field_name("pattern"));
            let right = node
                .child_by_field_name("right")
                .or_else(|| node.child_by_field_name("value"));
            if let (Some(left), Some(right)) = (left, right) {
                let name = text(left, source).to_string();
                let mut value = expression(right, source);
                if node.kind().contains("augmented") {
                    value = FlowExpr::Join {
                        values: vec![FlowExpr::Variable { name: name.clone() }, value],
                    };
                }
                let mut result = vec![];
                if name.ends_with(".innerHTML") || name.ends_with(".outerHTML") {
                    result.push(FlowStmt::Evaluate {
                        value: FlowExpr::Call {
                            name: "innerHTML".into(),
                            args: vec![value.clone()],
                            line,
                            snippet: snippet(node, source),
                            shell: false,
                        },
                    });
                }
                result.push(FlowStmt::Assign {
                    name,
                    value,
                    local: matches!(node.kind(), "variable_declarator" | "let_declaration"),
                    line,
                });
                result
            } else {
                vec![]
            }
        }
        "return_statement" | "return_expression" => vec![FlowStmt::Return {
            value: node
                .child_by_field_name("value")
                .or_else(|| named(node).first().copied())
                .map(|n| expression(n, source))
                .unwrap_or(FlowExpr::Literal),
        }],
        "if_statement" | "if_expression" | "elif_clause" => {
            let yes = node
                .child_by_field_name("consequence")
                .or_else(|| node.child_by_field_name("body"))
                .map(|n| statements(n, source))
                .unwrap_or_default();
            let no = node
                .child_by_field_name("alternative")
                .map(|n| statements(n, source))
                .unwrap_or_default();
            let mut result = node
                .child_by_field_name("condition")
                .map(|n| {
                    vec![FlowStmt::Evaluate {
                        value: expression(n, source),
                    }]
                })
                .unwrap_or_default();
            result.push(FlowStmt::Branch { yes, no });
            result
        }
        "else_clause" => named(node)
            .into_iter()
            .flat_map(|n| statements(n, source))
            .collect(),
        "for_statement" | "while_statement" | "for_expression" | "while_expression"
        | "for_in_statement" | "loop_expression" => {
            let mut result = vec![];
            if let Some(condition) = node.child_by_field_name("condition") {
                result.push(FlowStmt::Evaluate {
                    value: expression(condition, source),
                });
            }
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                result.push(FlowStmt::Assign {
                    name: text(left, source).into(),
                    value: expression(right, source),
                    local: false,
                    line,
                });
            }
            result.push(FlowStmt::Loop {
                body: node
                    .child_by_field_name("body")
                    .map(|n| statements(n, source))
                    .unwrap_or_default(),
            });
            result
        }
        "import_statement" | "import_from_statement" | "use_declaration" => vec![],
        _ => vec![FlowStmt::Evaluate {
            value: expression(node, source),
        }],
    }
}
fn parameters(node: Node<'_>, source: &str) -> Vec<String> {
    node.child_by_field_name("parameters")
        .or_else(|| node.child_by_field_name("parameter"))
        .map(|n| {
            if n.kind() == "identifier" {
                return vec![text(n, source).into()];
            }
            named(n)
                .into_iter()
                .filter_map(|p| {
                    let p = p
                        .child_by_field_name("pattern")
                        .or_else(|| p.child_by_field_name("name"))
                        .unwrap_or(p);
                    if p.kind() == "identifier" {
                        Some(text(p, source).into())
                    } else {
                        named(p)
                            .into_iter()
                            .find(|n| n.kind() == "identifier")
                            .map(|n| text(n, source).into())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
fn imports(node: Node<'_>, source: &str) -> Vec<ImportRecord> {
    let raw = text(node, source).trim().trim_end_matches(';');
    let line = node.start_position().row + 1;
    let mut result = vec![];
    if let Some(rest) = raw.strip_prefix("from ") {
        if let Some((module, names)) = rest.split_once(" import ") {
            for item in names.trim_matches(['(', ')']).split(',') {
                let parts = item.split_whitespace().collect::<Vec<_>>();
                if parts.is_empty() {
                    continue;
                }
                result.push(ImportRecord {
                    module: module.trim().into(),
                    imported: parts[0].into(),
                    local: parts.last().unwrap().to_string(),
                    line,
                });
            }
        }
    } else if let Some(rest) = raw.strip_prefix("import ") {
        if let Some(module) = node.child_by_field_name("source") {
            let module = text(module, source).trim_matches(['\'', '"']).to_string();
            let clause = rest.split(" from ").next().unwrap_or("");
            let names = clause.trim().trim_matches(['{', '}']);
            for item in names.split(',') {
                let parts = item.split_whitespace().collect::<Vec<_>>();
                if parts.is_empty() {
                    continue;
                }
                let imported = if parts[0] == "*" { "*" } else { parts[0] };
                result.push(ImportRecord {
                    module: module.clone(),
                    imported: imported.into(),
                    local: parts.last().unwrap().trim_matches(['{', '}']).into(),
                    line,
                });
            }
        } else {
            for item in rest.split(',') {
                let parts = item.split_whitespace().collect::<Vec<_>>();
                if parts.is_empty() {
                    continue;
                }
                result.push(ImportRecord {
                    module: parts[0].into(),
                    imported: "*".into(),
                    local: parts.last().unwrap().to_string(),
                    line,
                });
            }
        }
    } else if let Some(rest) = raw.strip_prefix("use ") {
        let parts = rest.split(" as ").collect::<Vec<_>>();
        let qualified = parts[0].trim();
        if let Some((module, name)) = qualified.rsplit_once("::") {
            result.push(ImportRecord {
                module: module.into(),
                imported: name.into(),
                local: parts.last().unwrap().rsplit("::").next().unwrap().into(),
                line,
            });
        }
    }
    result
}
fn collect_expr(value: &FlowExpr, owner: &str, file: &str, out: &mut IndexedFile) {
    match value {
        FlowExpr::Source { name, line } => annotate(
            owner,
            file,
            *line,
            "source",
            "untrusted-input",
            name,
            name,
            out,
        ),
        FlowExpr::Call {
            name,
            args,
            line,
            snippet,
            shell,
        } => {
            out.calls.push(CallSite {
                owner: owner.into(),
                name: name.clone(),
                line: *line,
                snippet: snippet.clone(),
            });
            if let Some((kind, _)) = sink_type(name, *shell) {
                annotate(owner, file, *line, "sink", kind, name, snippet, out);
            }
            if let Some(kind) = sanitizer_type(name) {
                annotate(owner, file, *line, "sanitizer", kind, name, snippet, out);
            }
            if let Some(kind) = guard_type(name) {
                annotate(
                    owner,
                    file,
                    *line,
                    "security_guard",
                    kind,
                    name,
                    snippet,
                    out,
                );
            }
            for arg in args {
                collect_expr(arg, owner, file, out);
            }
        }
        FlowExpr::Join { values } => {
            for value in values {
                collect_expr(value, owner, file, out);
            }
        }
        _ => {}
    }
}
fn collect_statements(body: &[FlowStmt], owner: &str, file: &str, out: &mut IndexedFile) {
    for statement in body {
        match statement {
            FlowStmt::Assign { value, .. }
            | FlowStmt::Evaluate { value }
            | FlowStmt::Return { value } => collect_expr(value, owner, file, out),
            FlowStmt::Branch { yes, no } => {
                collect_statements(yes, owner, file, out);
                collect_statements(no, owner, file, out);
            }
            FlowStmt::Loop { body } | FlowStmt::Scope { body } => {
                collect_statements(body, owner, file, out)
            }
        }
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "annotation fields mirror the persisted evidence contract"
)]
fn annotate(
    owner: &str,
    file: &str,
    line: usize,
    kind: &str,
    category: &str,
    name: &str,
    snippet: &str,
    out: &mut IndexedFile,
) {
    out.annotations.push(Annotation {
        id: identity((owner, line, kind, name)),
        owner: owner.into(),
        kind: kind.into(),
        category: category.into(),
        name: name.into(),
        location: Location {
            file: file.into(),
            start_line: line,
            end_line: line,
        },
        snippet: snippet.chars().take(240).collect(),
    });
}
fn method_owner(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(node) = parent {
        match node.kind() {
            "class_definition" | "class_declaration" | "impl_item" => return true,
            "function_definition"
            | "function_declaration"
            | "function_item"
            | "arrow_function"
            | "method_definition" => return false,
            _ => parent = node.parent(),
        }
    }
    false
}
fn visit(
    node: Node<'_>,
    source: &str,
    scope: &str,
    project: &str,
    path: &str,
    out: &mut IndexedFile,
    counts: &mut BTreeMap<String, usize>,
) {
    let kind = match node.kind() {
        "function_definition"
        | "function_declaration"
        | "function_item"
        | "arrow_function"
        | "function_expression" => Some("function"),
        "method_definition" => Some("method"),
        "class_definition" | "class_declaration" => Some("class"),
        "struct_item" => Some("struct"),
        "mod_item" => Some("module"),
        "impl_item" => Some("module"),
        _ => None,
    };
    let mut child_scope = scope.to_string();
    if let Some(mut kind) = kind {
        let name_node = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("type"));
        let name = name_node
            .map(|n| text(n, source).into())
            .or_else(|| {
                node.parent()
                    .and_then(|p| p.child_by_field_name("name"))
                    .map(|n| text(n, source).into())
            })
            .unwrap_or_else(|| "anonymous".to_string());
        let qualified = if scope.is_empty() {
            name.clone()
        } else {
            format!("{scope}.{name}")
        };
        if kind == "function" && method_owner(node) {
            kind = "method";
        }
        let key = format!("{qualified}:{kind}");
        let ordinal = counts.entry(key).or_default();
        *ordinal += 1;
        let id = identity((project, path, &qualified, kind, *ordinal));
        let mut body = node
            .child_by_field_name("body")
            .map(|n| {
                if node.kind() == "arrow_function"
                    && !matches!(n.kind(), "statement_block" | "block")
                {
                    vec![FlowStmt::Return {
                        value: expression(n, source),
                    }]
                } else {
                    if matches!(n.kind(), "block" | "statement_block") {
                        named(n)
                            .into_iter()
                            .flat_map(|n| statements(n, source))
                            .collect()
                    } else {
                        statements(n, source)
                    }
                }
            })
            .unwrap_or_default();
        if node.kind() == "function_item" {
            if let Some(last) = node
                .child_by_field_name("body")
                .and_then(|b| named(b).last().copied())
            {
                if !matches!(
                    last.kind(),
                    "expression_statement" | "let_declaration" | "return_expression"
                ) && kind != "module"
                {
                    body.pop();
                    body.push(FlowStmt::Return {
                        value: expression(last, source),
                    });
                }
            }
        }
        let symbol = SymbolRecord {
            id: id.clone(),
            name,
            qualified_name: qualified.clone(),
            kind: kind.into(),
            location: Location {
                file: path.into(),
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
            },
            language: out.language.clone(),
            content_hash: identity(text(node, source)),
            parameters: parameters(node, source),
            body,
        };
        collect_statements(&symbol.body, &id, path, out);
        if let Some(parent) = node.parent().filter(|p| p.kind() == "decorated_definition") {
            for decorator in named(parent)
                .into_iter()
                .filter(|n| n.kind() == "decorator")
            {
                let value = text(decorator, source).trim_start_matches('@');
                let name = value.split('(').next().unwrap_or(value);
                if let Some(category) = guard_type(name) {
                    annotate(
                        &id,
                        path,
                        decorator.start_position().row + 1,
                        "security_guard",
                        category,
                        name,
                        &snippet(decorator, source),
                        out,
                    );
                }
                if name.ends_with(".route") {
                    annotate(
                        &id,
                        path,
                        decorator.start_position().row + 1,
                        "endpoint",
                        "http-route",
                        name,
                        &snippet(decorator, source),
                        out,
                    );
                }
            }
        }
        out.symbols.push(symbol);
        child_scope = qualified;
    }
    if matches!(
        node.kind(),
        "import_statement" | "import_from_statement" | "use_declaration"
    ) {
        out.imports.extend(imports(node, source));
    }
    for child in named(node) {
        visit(child, source, &child_scope, project, path, out, counts);
    }
}
/// Parse supported source into persisted graph evidence without executing repository code.
pub fn extract_security_file(
    project: &str,
    path: &str,
    source: &str,
) -> crate::Result<IndexedFile> {
    let language = crate::detect_language(Path::new(path))
        .ok_or_else(|| crate::AstError::Parse("unsupported language".into()))?;
    let grammar = if path.ends_with(".tsx") || path.ends_with(".jsx") {
        "tsx"
    } else {
        language.as_str()
    };
    let tree = crate::parse_tree(source.as_bytes(), grammar)?;
    crate::validate_tree(&tree)?;
    let mut pending = vec![(tree.root_node(), 0usize)];
    let mut count = 0usize;
    let mut unsupported = std::collections::BTreeSet::new();
    while let Some((node, depth)) = pending.pop() {
        count += 1;
        if matches!(
            node.kind(),
            "try_statement"
                | "with_statement"
                | "switch_statement"
                | "match_statement"
                | "match_expression"
                | "object_pattern"
                | "array_pattern"
                | "tuple_pattern"
        ) {
            unsupported.insert(format!(
                "{path}:{}: {} has approximate/unsupported security flow semantics",
                node.start_position().row + 1,
                node.kind()
            ));
        }
        if count > 20000 || depth > 128 {
            return Err(crate::AstError::Parse(
                "security AST budget exceeded (20000 nodes / depth 128)".into(),
            ));
        }
        pending.extend(named(node).into_iter().map(|n| (n, depth + 1)));
    }
    let mut out = IndexedFile {
        semantics_revision: ANALYSIS_SEMANTICS_REVISION,
        path: path.into(),
        language,
        content_hash: identity(source),
        symbols: vec![],
        imports: vec![],
        calls: vec![],
        annotations: vec![],
        notes: unsupported.into_iter().collect(),
    };
    visit(
        tree.root_node(),
        source,
        "",
        project,
        path,
        &mut out,
        &mut BTreeMap::new(),
    );
    // Top-level executable statements have a module owner, including scripts without functions.
    let owner = identity((project, path, "<module>"));
    let body = statements(tree.root_node(), source);
    collect_statements(&body, &owner, path, &mut out);
    out.symbols.push(SymbolRecord {
        id: owner,
        name: "<module>".into(),
        qualified_name: path.into(),
        kind: "module".into(),
        location: Location {
            file: path.into(),
            start_line: 1,
            end_line: source.lines().count().max(1),
        },
        language: out.language.clone(),
        content_hash: out.content_hash.clone(),
        parameters: vec![],
        body,
    });
    out.annotations.sort_by(|a, b| a.id.cmp(&b.id));
    out.annotations.dedup_by(|a, b| a.id == b.id);
    out.calls
        .sort_by(|a, b| (&a.owner, a.line, &a.name).cmp(&(&b.owner, b.line, &b.name)));
    out.calls
        .dedup_by(|a, b| a.owner == b.owner && a.line == b.line && a.name == b.name);
    Ok(out)
}
