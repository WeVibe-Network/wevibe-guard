<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:02100a,100:2fe07a&height=160&section=header&text=wevibe-guard&fontColor=54f59a&fontSize=42&fontAlignY=40&desc=Prompt-injection%20and%20secret%20scanner&descAlignY=64&descSize=16" alt="wevibe-guard" width="100%" />

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
[![status-alpha](https://img.shields.io/badge/status-alpha-ffc266?style=flat-square)](https://github.com/WeVibe-Network)
[![license-Apache--2.0](https://img.shields.io/badge/license-Apache--2.0-82aaff?style=flat-square)](LICENSE)
[![docs-wevibe-docs](https://img.shields.io/badge/docs-wevibe--docs-54f59a?style=flat-square)](https://github.com/WeVibe-Network/wevibe-docs)
[![%40WeVibe__Network](https://img.shields.io/badge/%40WeVibe__Network-0a0a0a?style=flat-square&logo=x&logoColor=white)](https://x.com/WeVibe_Network)

</div>

---

Fast prompt-injection, credential, and exfiltration scanner for WeVibe memories.

## Overview

`wevibe-guard` is a Rust security scanner (`edition = 2021`) built on YARA-X.
It is published as both:

- a library crate: `wevibe_guard`
- a CLI binary: `wevibe-guard`

The scanner combines signature rules and pattern-based heuristics to detect high-signal threats in memory text, keywords, and metadata.

This project is in active alpha and is designed to provide strong, deterministic warnings while the broader moderation and approval flow continues to evolve.

## Role in the WeVibe Network

`wevibe-guard` runs locally in client workflows at two points:

- **submission time** (advisory scan before new memory content is sent)
- **recall time** (pre-injection scan before memory is provided to an agent)

Integrations (including MCP and plugins) typically invoke it via `WEVIBE_GUARD_BIN`.

Guard is **advisory** by design: it warns and surfaces detections, but does not block automatically. The human approver remains the primary security boundary.

## Detection coverage

Current rule and heuristic coverage includes:

- YARA-signature prompt injection patterns (instruction bypass, role hijack, jailbreak/system prompt extraction)
- credential leakage patterns (AWS keys/secrets, token formats, connection strings)
- Unicode mathematical-alphanumeric / homoglyph injection indicators
- Base64-encoded injection and credential payloads
- suspicious URLs, hostnames, and IPv4 endpoints
- malicious dependency/config directives and suspicious outbound install patterns
- shell-command exfiltration patterns (including curl/wget-style execution chains)

Guard does **not** fully solve semantic natural-language attacks on its own. Those are mitigated through human review and reputation/moderation controls.

## Getting started

### Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

### Run the CLI

The CLI reads a JSON request from `stdin` and prints JSON findings to `stdout`.

Example:

```bash
printf '{"memory":{"text":"hello"},"stack":[],"include_flags":true}' | ./target/debug/wevibe-guard
```

## Testing

Run tests:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

## Configuration

- Set `WEVIBE_GUARD_BIN` in calling applications to point to the preferred guard executable.
- The CLI accepts structured memory input (`text`, optional `keywords`, optional `metadata`) and returns detections plus optional heuristic flags.

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for current status and planned improvements.

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
