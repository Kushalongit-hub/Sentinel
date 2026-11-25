# Framework source and native flow contracts

These are bounded lexical contracts, not runtime framework identity or route
reachability proof. Findings remain candidates for review.

| Contract | Current recognition | Important limits |
|---|---|---|
| Conventional requests | `req` / `request` body, query, arguments, headers and cookies | Name-based; unrelated objects can cause false positives; renamed receivers and middleware identity are not inferred |
| Express/Fastify | ESM factory imports or direct literal CommonJS require; Express Router(), literal-path HTTP registrations, inline/local handlers and simple identifier aliases; bounded inline/local Fastify plugin callbacks; first request parameter can be renamed | Dot-access query/body/params/headers/cookies fields are sources. Imported handlers/plugins, destructured require, chained/computed registrations, complex aliases and middleware/hooks remain unsupported; recognized unsupported registrations add incomplete coverage notes |
| FastAPI | Module-level imported `FastAPI` / `APIRouter` constructors, including direct and namespace import aliases; recognized HTTP decorators; explicitly typed `str` parameters without call-valued defaults | Other parameter/dependency forms add incomplete coverage notes. Models, factory-created receivers, nested routes and authentication are not modeled |
| Flask | Module-level imported `Flask` constructor, including namespace aliases, and `.route` / `.get` / `.post` / `.put` / `.patch` / `.delete` with positional or `rule=` literal path; implicit string, `string`, and `path` variables | Numeric/custom converters and dynamic/interpolated paths add incomplete coverage notes; Blueprint/factory receivers and other registration shapes are not modeled |
| Imports/calls | Named and namespace import aliases; nearest enclosing lexical function scopes | Ambiguous modules, default export identity, runtime rebinding and full type dispatch remain unresolved; no arbitrary first-match resolution |
| Object fields | First-level identifier-key JavaScript object literals; reassignment invalidates prior fields; branches merge root fallback taint | Computed/spread/shorthand/string keys stay aggregate; aliasing, nested fields and interprocedural object identity remain approximate |
| Async returns | Ordinary return propagation through resolved calls and awaited values | Scheduling, concurrency, promise callbacks, cancellation and exception semantics are not established |

Framework imports must be direct module-level statements before the decorated
function; nested/conditional and later imports provide no constructor evidence.
Imports and assignments are processed in source order: imports after a
constructor call cannot justify it, reimports restore constructor bindings, and
unrelated imports invalidate matching constructor/receiver names.
Receiver constructors must precede decorated functions; direct assignments to
constructor names or their namespace invalidate subsequent constructor evidence. A visible receiver reassignment to
an unrecognized value also removes constructor evidence. This is syntax evidence, not
verification of installed dependencies. `str` does not sanitize SQL. Separate SQL
parameters remain distinct from query text. Authorization decorators do not prove
guard dominance or resource ownership.

Source references: [Starlette request API](https://github.com/Kludex/starlette/blob/main/starlette/requests.py),
[Express cookie-parser](https://github.com/expressjs/cookie-parser/blob/master/README.md),
[FastAPI path parameters](https://fastapi.tiangolo.com/tutorial/path-params/),
[FastAPI parameter reference](https://fastapi.tiangolo.com/reference/parameters/),
[Flask route API](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.route),
and [Flask variable rules](https://flask.palletsprojects.com/en/stable/quickstart/#variable-rules).

Semantics revision 18 invalidates incompatible cached parses and baseline/job
detector identities. `request-metadata.json` and `phase2-native.json` supply paired
author-labelled development regressions, not independent or held-out evaluation.
Trace reports include native backend version/revision and the admitted source
snapshot identity. Legacy trace metadata remains unknown when absent.

JavaScript receiver and local handler bindings follow statement order in the module or admitted plugin body;
ordinary function declarations are hoisted. Reassignment/import replacement
invalidates the respective binding. Request fields are tainted independently;
the reply parameter is not a request source. Existing interprocedural summaries
propagate field-derived values into resolved helpers. Multiple route callbacks
may be analyzed as candidates but remain incomplete because middleware ordering,
request mutation and guard dominance are not modeled. Fastify plugin traversal is
limited to eight nesting levels and 256 expansions per inspection; exhausted
budgets, opaque registrations, options and addHook calls mark coverage incomplete.
Visible require shadowing is inherited by plugin scopes. Imported plugins, Express
mount reachability and runtime execution order need further contracts; absence of
framework proof is not proof that a route cannot exist at runtime.

Route API references: [Express ESM registration](https://expressjs.com/en/5x/api/)
and [Fastify shorthand and hooks](https://fastify.dev/docs/latest/Reference/Routes/).
`benchmarks/js-routes.json` adds eight paired author-labelled development cases.

`benchmarks/js-plugins.json` adds twelve paired development cases for CommonJS,
Router handler aliases and inline/named/nested local plugins. These are lexical
flow regressions; they do not establish framework runtime reachability.

Semantics revision 12 restricts plain calls through Python named imports to
module-level definitions. A same-named class method or nested function is not a
module export and cannot impersonate an imported function or make that function
spuriously ambiguous. Multiple matching module-level definitions remain unresolved.
This covers direct named imports, including aliases; namespace attribute chains,
runtime rebinding, dynamic exports and full class dispatch retain their existing
limitations. Existing revision-11 graph IR is reparsed, and baseline/job detector
identity changes rather than silently reusing prior semantics as current proof.

Revision 13 applies the module-scope rule to direct Python namespace calls too:
`import service as lib; lib.helper(value)` may bind only the module-level helper.
A named import permits a plain call to that binding; attribute access through
that imported value is not silently treated as a call to the binding itself.
Namespace module objects are not treated as callables, and deeper namespace/class attribute
chains remain unresolved because receiver/class dispatch is not modeled. These
rules preserve uncertainty rather than guessing from a matching short name.

Revision 14 limits lexical `self`/`this` method resolution to a direct member,
such as `self.helper()` or `this.helper()`. A deeper chain such as
`self.worker.helper()` has a different receiver and cannot be bound to the
current class's helper without receiver/type evidence. Such chains stay unresolved;
this does not add inheritance, object-field typing or runtime dispatch modeling.

Revision 15 skips enclosing Python class namespaces while resolving bare calls
inside methods or their nested functions. A bare helper() can bind an enclosing
function-local or module helper; it does not inherit a same-named class method.
Nearest function-local bindings retain priority. The class's own body lookup is
left unchanged; this does not add runtime class construction, rebinding, descriptors
or compiler-level scope/type proof. Direct receiver calls use their separate
bounded self/this contract.

Revision 16 scopes Python import/definition collision checks to module definitions
and enclosing lexical function scopes. A same-named method in an enclosing class,
or a nested helper inside an unrelated function, no longer suppresses a valid
module import. Visible module/function definition conflicts remain conservatively
unresolved, including enclosing function scopes around nested classes. This does
not model assignment/parameter rebinding, import statement scope, global/nonlocal
statements or source-order rebinding. Other language collision rules are unchanged.

Revision 17 records the lexical scope of Python import statements. Bare named and
direct namespace calls may use imports only from the current or enclosing function
scope or module, skipping class namespaces from method closures. The nearest
visible import binding wins; an unresolved nearer import cannot borrow an outer
import's target. Sibling-function imports do not become module bindings. Multiple
bindings in the same scope remain ambiguous. File-level IMPORTS dependency edges
still describe all syntactic imports, independently of call visibility. Legacy
records without scope deserialize as module scope; the semantics upgrade forces
source reparsing before current analysis uses them. This is bounded lexical
resolution, not proof of conditional execution, assignment/parameter rebinding,
global/nonlocal behavior, source ordering or runtime exports.

Revision 18 counts distinct candidate symbol identities when resolving calls.
Repeated named or namespace imports of the same static target no longer produce
artificial ambiguity. Repeated bindings that reach different modules/symbols, or
multiple same-named export definitions with distinct ordinal identities, remain
unresolved. Syntactic import/dependency records are retained. Runtime import hooks,
rebinding and dynamic exports remain outside the bounded static import contract.
