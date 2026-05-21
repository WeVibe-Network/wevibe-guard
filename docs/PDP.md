# WeVibe Guard PDP

## CLI & API Surface

| Interface | Description |
|-----------|-------------|
| gRPC `Scan(stream Buffer)` | Streaming API used by wevibe-mcp; returns incremental detection events and final summary. |
| CLI `wevibe-guard scan <path>` | Scan files or stdin; flags: `--json`, `--rules`, `--fail-on-warning`. |
| REST `/scan` (optional) | Disabled by default; can be enabled for air-gapped dashboards. |

## Configuration

- `guard.toml`
  - `[rules]` enable/disable default packs (`prompt_injection`, `credentials`, `unicode`, `heuristics`).
  - `[ocr]` toggle OCR phase and set `max_bytes` threshold.
  - `[logging]` severity (`info|warn|debug`), file path.
- Runtime flags: `--rules-dir`, `--no-ocr`, `--strict` (treat warnings as fatal).

## Build & Test

- Rust edition 2021.
- `cargo test` executes rule-pack regression suite with fixture corpus.
- `cargo xtask package` builds static binaries for macOS/Linux and runs `scripts/validate-rules.sh`.

## Dependencies

- `yara-x` crate for rule execution.
- `image` + `leptonica` + `tesseract` for OCR fallback.
- `serde_json` for structured reporting.
- Optional `tonic` + `prost` when gRPC is enabled.

## Diagnostics

- Logs shipped to `~/.wevibe/logs/guard.log` with JSON formatting.
- Prometheus metrics (optional) expose rule hit counts and scan latency when built with `metrics` feature flag.

## Security Considerations

- Guard never transmits scan data; results stay local.
- Rule packs validated to avoid catastrophic backtracking.
- OCR temp files stored under `~/.wevibe/tmp` and securely deleted after use.

## Release Checklist

1. Update rule pack version and changelog.
2. Run `cargo test && cargo clippy -- -D warnings`.
3. Package binaries via `cargo xtask package`.
4. Publish artifact checksums and signature manifest.

## Sprint 24 Updates

- Documented the Accept / Deny / Report plugin flow, including the new best-effort report POST to wevibe-hub.
- Configuration notes reference the moderation quorum so operators understand when guard results lead to ready-state promotion.
- Tests include fixtures covering report submissions and moderator approval metadata.
