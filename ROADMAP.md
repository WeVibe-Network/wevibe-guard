## Status

- Alpha-stage Rust scanner with a working library (`wevibe_guard`) and CLI (`wevibe-guard`).
- YARA-X-backed signatures and heuristics are active for prompt injection, credential leakage, exfiltration indicators, and suspicious configuration/install patterns.
- Integrated into local submission and recall workflows as an advisory security layer before memory injection.

## Near-term

- Add dedicated zero-width character detection.
- Add bidirectional override (bidi) detection for hidden-text prompt manipulation.
- Continue rule expansion and fixture coverage to improve threat recall while controlling false positives.

## Future

- Broaden multilingual and obfuscation-aware detection patterns.
- Improve artifact extraction and scoring for clearer moderator triage.
- Continue tuning scanner ergonomics for plugin, MCP, and local developer workflows.

## Design references

- WeVibe docs: https://github.com/WeVibe-Network/wevibe-docs
