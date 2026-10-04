# Patch regression fixture

Copy this directory to a temporary Git repository, commit `routes.py`, and run
`sentinel baseline create .`. Verify unchanged debt, replace the execute call
with `cursor.execute('SELECT ?', (value,))`, verify the fix, then restore the
original interpolation and verify REGRESSED / FAIL. `tests/graph.rs` automates
this lifecycle. The stdio integration test also edits a file between agent calls
and validates PASS for a fix and FAIL for a newly introduced command flow.

These fixture files are analysis input and are never executed by Sentinel.
