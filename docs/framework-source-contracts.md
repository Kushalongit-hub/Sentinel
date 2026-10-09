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

Semantics revision 11 invalidates incompatible cached parses and baseline/job
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
