# Architecture

## Database schema

Seven tables, six of them linked by `sl_no` (session number) from the
`history` table; `settings` is a standalone single-row table for runtime
configuration. Source of truth: [`docker/schema.sql`](../docker/schema.sql)
— update this diagram if it drifts.

```
history              ← one row per scan session (sl_no is the spine)
    │
    ├── vulnerabilities   ← vulns found, linked by sl_no
    │       │
    │       └── fixes     ← fixes per vuln, linked by vuln_id + sl_no
    │
    ├── exploit_suggestions ← AI-proposed exploit ideas (name/rationale/tool/safe validation), linked by sl_no
    │
    ├── ai_tool_calls      ← every AI-dispatched [TOOL:]/[SEARCH:] call, blocked or not, linked by sl_no
    │
    └── summary           ← full AI analysis dump, linked by sl_no

settings              ← single row: active provider, model, timeouts, API key
                         (read/written from both the web UI and the CLI Settings screen)
```

For the top-level file/package layout, see the "Project Structure" section
in the main [README](../README.md).
