# WeVibe Guard Whitepaper

Version: 1.1 · Sprint 24

## Purpose

WeVibe Guard is the local content sanitation engine that protects WeVibe memories against prompt injection, credential leakage, and steganographic payloads. It runs on every contribution and recall, ensuring that plaintext never reaches an agent without human oversight and machine screening.

## Design Goals

1. **Deterministic scanning** — rule packs compile to YARA-X bytecode for reproducible results across platforms.
2. **Zero plaintext exfiltration** — findings surface locally in the moderator UI; no scan telemetry leaves the machine.
3. **Layered detection** — combine signature rules, heuristics, OCR, and artifact extraction to cover diverse attack vectors.
4. **Extensibility** — operators can ship custom rule packs without recompiling the engine.

## Pipeline Overview

1. **Ingestion** — Guard accepts UTF-8 buffers, binary attachments, or filesystem paths.
2. **Normalization** — decode base64 and common encodings; canonicalize line endings.
3. **Signature phase** — run YARA-X rulesets grouped by severity (prompt injection, exfil, credential, base64 payload, unicode abuse).
4. **OCR phase** — render text to image (ImageMagick), OCR via Tesseract, re-run signature phase on OCR output.
5. **Heuristic phase** — pattern-based detection for shell pipes, package installs, suspicious regex combos.
6. **Artifact extraction** — emit URL/hostname/IP/shell command lists for moderator review.
7. **Reporting** — produce structured JSON consumed by wevibe-mcp and dashboard.

## Output Contract

```json
{
  "summary": {
    "severity": "warning|critical|info",
    "rules_triggered": ["..."],
    "has_credentials": true
  },
  "artifacts": {
    "urls": [...],
    "domains": [...],
    "ipv4": [...],
    "shell": [...]
  },
  "detections": [
    { "rule": "PROMPT_INJECTION_PIPE", "offset": 120, "excerpt": "..." }
  ]
}
```

## Integrations

- **wevibe-mcp** (Node): spawns guard via gRPC streaming API.
- **wevibe-cli**: exposes `wevibe guard scan` for CI workflows.
- **Dashboard**: renders guard findings directly in moderator UI.

## Rule Pack Governance

- Default packs versioned under `rules/` with semantic version tags.
- Operator overrides loaded from `~/.wevibe/guard.d/*.yarax`.
- CI script `scripts/validate-rules.sh` ensures new packs compile and avoid forbidden constructs.

## Future Work

- Signed rule pack updates with ed25519 manifest.
- GPU-accelerated OCR for large batch workloads.
- Heuristics for multi-language code blocks.

## Sprint 24 Updates

- Added Accept / Deny / Report controls to the OpenCode plugin, ensuring guard-vetted memories are only injected after explicit moderator approval or leader override.
- Guard now relays report actions to hub APIs, locking reported memories out of recall until the dashboard resolves them.
- Documentation links the guard output to hub `required_approvals`, clarifying how scan results feed into the refreshed quorum workflow.
