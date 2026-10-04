//! Bounded interpretation of AST-derived flow IR with parameter and return propagation.
use sentinel_core::security::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Clone)]
struct Origin {
    source: FlowStep,
    path: Vec<FlowStep>,
    sanitizers: Vec<FlowStep>,
    guards: Vec<FlowStep>,
    blocked: BTreeSet<String>,
    low: bool,
}
#[derive(Clone, Default)]
struct Value(Vec<Origin>, bool);
impl Value {
    fn merge(&mut self, other: Self) {
        self.1 |= other.1;
        for origin in other.0 {
            let key = identity((&origin.source, &origin.blocked));
            if !self
                .0
                .iter()
                .any(|o| identity((&o.source, &o.blocked)) == key)
            {
                if self.0.len() >= 32 {
                    self.1 = true;
                } else {
                    self.0.push(origin);
                }
            }
        }
    }
}
type Env = BTreeMap<String, Value>;
struct Interpreter<'a> {
    symbols: BTreeMap<&'a str, &'a SymbolRecord>,
    calls: BTreeMap<(String, usize, String), String>,
    annotations: Vec<&'a Annotation>,
    source_reachable: BTreeSet<String>,
    limits: TraceLimits,
    visited: usize,
    paths: BTreeMap<String, TaintPath>,
    notes: BTreeSet<String>,
    complete: bool,
}
fn step(symbol: &SymbolRecord, line: usize, operation: impl Into<String>) -> FlowStep {
    FlowStep {
        symbol: symbol.qualified_name.clone(),
        symbol_id: symbol.id.clone(),
        location: Location {
            file: symbol.location.file.clone(),
            start_line: line,
            end_line: line,
        },
        operation: operation.into(),
    }
}
impl Interpreter<'_> {
    fn budget(&mut self, depth: usize) -> bool {
        if depth > self.limits.max_call_depth
            || self.visited >= self.limits.max_nodes_visited
            || self.paths.len() >= self.limits.max_paths
        {
            self.complete = false;
            self.notes
                .insert("trace traversal limit reached; absence of a path is inconclusive".into());
            return false;
        }
        self.visited += 1;
        true
    }
    fn function(&mut self, symbol: &SymbolRecord, args: Vec<Value>, depth: usize) -> Value {
        if !self.budget(depth) {
            return Value::default();
        }
        let mut env = Env::new();
        for (name, value) in symbol.parameters.iter().zip(args) {
            env.insert(name.clone(), value);
        }
        let mut guards = self
            .annotations
            .iter()
            .filter(|a| a.owner == symbol.id && a.kind == "security_guard")
            .map(|a| step(symbol, a.location.start_line, &a.name))
            .collect::<Vec<_>>();
        let mut returns = Value::default();
        self.statements(
            &symbol.body,
            symbol,
            &mut env,
            &mut guards,
            &mut returns,
            depth,
        );
        if returns.1 || env.values().any(|v| v.1) {
            self.complete = false;
            self.notes.insert(
                "taint origin limit reached (32); absence of further flows is inconclusive".into(),
            );
        }
        returns
    }
    fn evaluate(
        &mut self,
        value: &FlowExpr,
        symbol: &SymbolRecord,
        env: &Env,
        guards: &mut Vec<FlowStep>,
        depth: usize,
    ) -> Value {
        if !self.budget(depth) {
            return Value::default();
        }
        let result = match value {
            FlowExpr::Literal => Value::default(),
            FlowExpr::Variable { name } => env
                .get(name)
                .or_else(|| env.get(name.split('.').next().unwrap_or(name)))
                .cloned()
                .unwrap_or_default(),
            FlowExpr::Source { name, line } => {
                let source = step(symbol, *line, name);
                Value(
                    vec![Origin {
                        source: source.clone(),
                        path: vec![source],
                        sanitizers: vec![],
                        guards: guards.clone(),
                        blocked: BTreeSet::new(),
                        low: false,
                    }],
                    false,
                )
            }
            FlowExpr::Join { values } => {
                let mut result = Value::default();
                for value in values {
                    result.merge(self.evaluate(value, symbol, env, guards, depth));
                }
                result
            }
            FlowExpr::Call {
                name,
                args,
                line,
                snippet,
                shell,
            } => {
                let mut arguments = args
                    .iter()
                    .map(|arg| self.evaluate(arg, symbol, env, guards, depth))
                    .collect::<Vec<_>>();
                if let Some(category) = guard_type(name) {
                    guards.push(step(symbol, *line, format!("{category}: {name}")));
                }
                if let Some((category, position)) = sink_type(name, *shell) {
                    if let Some(value) = arguments.get(position) {
                        for origin in &value.0 {
                            if origin.blocked.contains(category) {
                                continue;
                            }
                            let sink = step(symbol, *line, name);
                            let mut path = origin.path.clone();
                            path.push(sink.clone());
                            let id = identity((
                                &origin.source.symbol_id,
                                &origin.source.operation,
                                &sink.symbol_id,
                                category,
                                snippet,
                                path.iter()
                                    .map(|s| (&s.symbol_id, &s.operation))
                                    .collect::<Vec<_>>(),
                            ));
                            let mut security_guards = origin.guards.clone();
                            security_guards.extend(guards.clone());
                            security_guards.sort_by(|a, b| {
                                (&a.symbol_id, a.location.start_line)
                                    .cmp(&(&b.symbol_id, b.location.start_line))
                            });
                            security_guards.dedup_by(|a, b| {
                                a.symbol_id == b.symbol_id && a.location == b.location
                            });
                            if self.paths.len() >= self.limits.max_paths
                                && !self.paths.contains_key(&id)
                            {
                                self.complete = false;
                                self.notes.insert(
                                    "taint path limit reached; additional paths omitted".into(),
                                );
                                break;
                            }
                            self.paths.entry(id.clone()).or_insert(TaintPath{id,source:origin.source.clone(),path,sink,sink_type:category.into(),sanitizers:origin.sanitizers.clone(),security_guards,
                                confidence:if origin.low{"low"}else{"medium"}.into(),
                                evidence:format!("AST-derived input {} flows through parameter/return assignments to {name} ({category}) at {}:{line}. No recognized category-specific sanitizer blocks this value. Call/API identity is syntactic, and guard annotations do not prove protection.",origin.source.operation,symbol.location.file),
                                remediation_hint:match category{"sql-injection"=>"Use a constant SQL statement with bound parameters; do not interpolate untrusted query text.","command-injection"=>"Avoid a shell; invoke a fixed executable with a structured argument list.","xss"=>"Encode output for its rendering context or use a safe text API.",_=>"Constrain file access to an allowed root after canonicalization and validate the input path."}.into()});
                        }
                    }
                }
                if let Some(id) = self
                    .calls
                    .get(&(symbol.id.clone(), *line, name.clone()))
                    .cloned()
                {
                    if let Some(callee) = self.symbols.get(id.as_str()).copied() {
                        if arguments.iter().all(|a| a.0.is_empty())
                            && !self.source_reachable.contains(&id)
                        {
                            return Value::default();
                        }
                        for value in &mut arguments {
                            for origin in &mut value.0 {
                                origin.path.push(step(
                                    callee,
                                    callee.location.start_line,
                                    format!("call {name}"),
                                ));
                                origin.guards.extend(guards.clone());
                            }
                        }
                        let mut result = self.function(callee, arguments, depth + 1);
                        for origin in &mut result.0 {
                            origin
                                .path
                                .push(step(symbol, *line, format!("return from {name}")));
                        }
                        return result;
                    }
                }
                let mut result = Value::default();
                for argument in arguments {
                    result.merge(argument);
                }
                if let Some((receiver, _)) = name.rsplit_once('.') {
                    result.merge(
                        env.get(receiver)
                            .or_else(|| env.get(receiver.split('.').next().unwrap_or(receiver)))
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                if let Some(category) = sanitizer_type(name) {
                    for origin in &mut result.0 {
                        origin.blocked.insert(category.into());
                        origin.sanitizers.push(step(symbol, *line, name));
                    }
                } else if sink_type(name, *shell).is_none() && !result.0.is_empty() {
                    for origin in &mut result.0 {
                        origin.low = true;
                    }
                    self.notes.insert("unresolved call return values conservatively retain argument/receiver taint; confidence is low".into());
                }
                result
            }
        };
        if result.1 {
            self.complete = false;
            self.notes
                .insert("taint origin limit reached (32); further flows may be omitted".into());
        }
        result
    }
    fn statements(
        &mut self,
        body: &[FlowStmt],
        symbol: &SymbolRecord,
        env: &mut Env,
        guards: &mut Vec<FlowStep>,
        returns: &mut Value,
        depth: usize,
    ) {
        for statement in body {
            if !self.budget(depth) {
                return;
            }
            match statement {
                FlowStmt::Assign { name, value, .. } => {
                    let value = self.evaluate(value, symbol, env, guards, depth);
                    env.insert(name.clone(), value);
                }
                FlowStmt::Evaluate { value } => {
                    self.evaluate(value, symbol, env, guards, depth);
                }
                FlowStmt::Return { value } => {
                    returns.merge(self.evaluate(value, symbol, env, guards, depth));
                    return;
                }
                FlowStmt::Branch { yes, no } => {
                    let mut branch = env.clone();
                    let mut branch_guards = guards.clone();
                    self.statements(yes, symbol, &mut branch, &mut branch_guards, returns, depth);
                    self.statements(no, symbol, env, guards, returns, depth);
                    for (name, value) in branch {
                        env.entry(name).or_default().merge(value);
                    }
                }
                FlowStmt::Loop { body } => {
                    for _ in 0..4 {
                        let mut iteration = env.clone();
                        self.statements(body, symbol, &mut iteration, guards, returns, depth);
                        for (name, value) in iteration {
                            env.entry(name).or_default().merge(value);
                        }
                    }
                    self.notes.insert("loop analysis uses four conservative iterations; complex loop-carried flows may require review".into());
                }
                FlowStmt::Scope { body } => {
                    let mut nested = env.clone();
                    self.statements(body, symbol, &mut nested, guards, returns, depth);
                    let locals = body
                        .iter()
                        .filter_map(|s| match s {
                            FlowStmt::Assign {
                                name, local: true, ..
                            } => Some(name.as_str()),
                            _ => None,
                        })
                        .collect::<BTreeSet<_>>();
                    for (name, value) in nested {
                        if !locals.contains(name.as_str()) {
                            env.insert(name, value);
                        }
                    }
                }
            }
        }
    }
}
/// Trace potential untrusted flows across unambiguous local/imported call edges.
/// Limits are enforced globally, and ambiguous dynamic calls remain conservative.
pub fn trace_project(
    files: &[IndexedFile],
    edges: &[SecurityEdge],
    limits: TraceLimits,
) -> TraceReport {
    let start = Instant::now();
    let symbols = files
        .iter()
        .flat_map(|f| &f.symbols)
        .map(|s| (s.id.as_str(), s))
        .collect::<BTreeMap<_, _>>();
    let calls = edges
        .iter()
        .filter(|e| e.kind == "CALLS" && e.resolved)
        .map(|e| ((e.from.clone(), e.line, e.name.clone()), e.to.clone()))
        .collect();
    let annotations = files
        .iter()
        .flat_map(|f| &f.annotations)
        .collect::<Vec<_>>();
    let mut source_reachable = annotations
        .iter()
        .filter(|a| a.kind == "source")
        .map(|a| a.owner.clone())
        .collect::<BTreeSet<_>>();
    loop {
        let old = source_reachable.len();
        for e in edges.iter().filter(|e| e.kind == "CALLS" && e.resolved) {
            if source_reachable.contains(&e.to) {
                source_reachable.insert(e.from.clone());
            }
        }
        if source_reachable.len() == old {
            break;
        }
    }
    let mut interpreter = Interpreter {
        symbols,
        calls,
        annotations,
        source_reachable,
        limits,
        visited: 0,
        paths: BTreeMap::new(),
        notes: BTreeSet::new(),
        complete: true,
    };
    let roots = interpreter
        .symbols
        .values()
        .copied()
        .filter(|s| !s.body.is_empty())
        .collect::<Vec<_>>();
    for symbol in roots {
        interpreter.function(symbol, vec![], 0);
    }
    TraceReport {
        paths: interpreter
            .paths
            .into_values()
            .take(limits.max_paths)
            .collect(),
        nodes_visited: interpreter.visited,
        duration_ms: start.elapsed().as_millis(),
        complete: interpreter.complete,
        coverage_notes: interpreter.notes.into_iter().collect(),
    }
}
