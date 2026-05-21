# WeVibe Guard Topology

## Process Layout

```
+----------------------+        +------------------+
| wevibe-mcp (Node)      |<------>| wevibe-guard gRPC  |
|                      |        | service / CLI    |
+----------------------+        +------------------+
          |                            |
          |                            |
          v                            v
   Session buffers               Rule packs (.yarax)
          |                            |
          v                            v
   JSON findings  <-----------------  OCR pipeline
```

## Execution Phases

1. **Normalization** — canonicalize line endings, decode base64, trim control chars.
2. **Signature Scan** — apply YARA-X packs in severity order; bail early on critical hits when `--strict` is enabled.
3. **OCR Loop** — when rules flag unicode anomalies, text is rendered → OCR’d → rescanned.
4. **Heuristics** — detect suspicious pipes, package installs, AI self-references.
5. **Artifact Extraction** — gather URLs/domains/IPs/shell commands into structured arrays.

## Data Stores

- `rules/` — bundled rule packs versioned with the repo.
- `~/.wevibe/guard.d/` — operator overrides.
- `~/.wevibe/tmp/` — transient OCR artefacts (deleted after scan).
- `~/.wevibe/logs/guard.log` — JSON log stream.

## Interfaces

| Interface | Direction | Notes |
|-----------|-----------|-------|
| gRPC `Scan` | bi-directional | Streaming input/output; used by wevibe-mcp. |
| CLI STDOUT | uni-directional | JSON or human-readable results. |
| Prometheus `/metrics` | optional pull | Exposed when built with `metrics` feature. |

## Deployment Patterns

- **Sidecar mode (default):** wevibe-mcp spawns guard per request.
- **Daemon mode:** guard runs as long-lived gRPC server; IDE plugins or dashboards connect directly.
- **CI/CD mode:** CLI invoked in pipelines to scan generated docs or code output.

## Observability

- Structured logs include rule name, severity, span offsets, and truncated excerpts.
- Optional metrics track scans per minute, OCR usage, and rule hit counts.
- Exit codes: `0` success, `2` warning (non-fatal), `3` critical detection.

## Sprint 24 Notes

- Guard now feeds Accept / Deny / Report actions in the OpenCode plugin, preventing injection until hub quorum promotes the memory.
- Reported memories trigger hub API calls, so daemon deployments should allow outbound access to `/api/v1/orgs/{orgID}/reports`.
- Metrics capture counts for each decision path (accept/deny/report) to aid dashboard analytics.
