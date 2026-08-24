<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:02100a,100:2fe07a&height=160&section=header&text=wevibe-guard&fontColor=54f59a&fontSize=42&fontAlignY=40&desc=Prompt-injection%20and%20secret%20scanner&descAlignY=64&descSize=16" alt="wevibe-guard" width="100%" />

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
[![status-alpha](https://img.shields.io/badge/status-alpha-ffc266?style=flat-square)](https://github.com/WeVibe-Network)
[![license-Apache--2.0](https://img.shields.io/badge/license-Apache--2.0-82aaff?style=flat-square)](LICENSE)
[![docs-wevibe-docs](https://img.shields.io/badge/docs-wevibe--docs-54f59a?style=flat-square)](https://github.com/WeVibe-Network/wevibe-docs)
[![%40WeVibe__Network](https://img.shields.io/badge/%40WeVibe__Network-0a0a0a?style=flat-square&logo=x&logoColor=white)](https://x.com/WeVibe_Network)

</div>

---

Advisory prompt-injection, credential, and exfiltration scanner for WeVibe candidate memories. It warns; it does not block.

## Overview

`wevibe-guard` is a Rust scanner (`edition = 2021`) built on YARA-X signature rules plus regex pattern rules. It ships as:

- a library crate: `wevibe_guard`
- a CLI binary: `wevibe-guard` (reads a JSON request on stdin, prints JSON findings on stdout)

It scans **candidate memories only** — the structured fields a memory carries (`text`, `keywords`, metadata values) — at the points where memory enters and leaves the network. It does not scan agent or user inputs.

The project is alpha. Its value is deliberately mechanical: it catches the attack classes a human reviewer cannot reliably eyeball — mathematical-alphanumeric steganography that renders like plain ASCII, Roman-numeral homoglyph substitution, Base64-obfuscated payloads, and pasted credentials — and surfaces them as findings. Guard itself is **fail-open**: it never blocks. The human reviewer remains the security boundary.

## Role in the WeVibe Network

Guard runs locally in client workflows at two points, because rules improve over time and yesterday-clean memories can match today's signatures:

- **Submission time** — advisory scan before candidate memory content is stored on-chain.
- **Recall time** — pre-injection scan before memory is handed to an agent.

Both scans are advisory by design:

- Detections are surfaced as findings for the reviewer; nothing is blocked or withheld automatically.
- The CLI exits `0` even when detections exist — a nonzero exit is not a "blocked memory", it is an operational error: unreadable input, oversized payload (1 MiB cap), or invalid JSON.
- Guard does not fully solve semantic natural-language attacks on its own. Those are mitigated through human review and reputation/moderation controls.

## Detection coverage

### Prompt injection (YARA signatures)

Six rules in `src/rules/injection.yar`: instruction-override/bypass phrases, role hijack, DAN-style jailbreak, system-prompt extraction, prompt-boundary/delimiter escape, and Unicode mathematical-alphanumeric injection (U+1D400–U+1D7FF: math-bold/script letters that look like ASCII but defeat naive string matching).

### Credential leakage (regex)

AWS access key IDs and secret access keys, OpenAI API keys (`sk-` formats), GitHub PAT/OAuth/fine-grained tokens (`ghp_`, `gho_`, `github_pat_`), `password`/`secret`/`token` assignments, `mongodb|postgres|mysql|redis://` connection strings, and `.env`-style `*_SECRET` assignments.

### Obfuscation — invisible to the eye

The part of the rule set a reviewer genuinely cannot do by eyeball:

- **Mathematical-alphanumeric injection** — text written in U+1D400–U+1D7FF codepoints that renders like ordinary letters while evading plain-text pattern matching.
- **Roman-numeral homoglyph substitution** — U+2160–216F glyphs swapped into injection keywords (e.g. a Roman numeral "Ⅰ" standing in for the letter I).
- **Base64-encoded payloads** — base64 blobs that decode to injection phrases or to credential patterns.

### Exfiltration

- **Suspicious outbound URL** — an HTTP-call verb (`fetch`, `curl`, `wget`, `requests.*`, `axios.*`, `urllib`) accompanied by a URL whose domain falls outside the built-in safe-domain allowlist.
- **Obfuscated install command** — malicious package-manager flags: pip `--index-url`/`--trusted-host`, npm/yarn/pnpm `--registry`/`--proxy`, `go get`, `cargo add --git`.

### Advisory heuristic flags (opt-in, not detections)

With `include_flags: true` the scan also returns advisory flags: `url`, `package_install`, `endpoint`, `config`, `connection_string`. These mark text worth a human glance at; they are not detections.

## Getting started

### Build

```bash
cargo build            # debug
cargo build --release  # release
```

### Run the CLI

The CLI reads one JSON request from stdin and prints JSON findings to stdout:

```bash
printf '{"memory":{"text":"hello"},"stack":[],"include_flags":true}' | ./target/debug/wevibe-guard
```

### Test

```bash
cargo test
cargo bench   # criterion benchmarks (scan_bench)
```

## Configuration

- `WEVIBE_GUARD_BIN` — set in calling applications to point at the preferred guard executable (MCP integrations and plugins invoke guard this way).
- Input shape: `memory.text` plus optional `keywords` and `metadata`, optional `include_flags`. Payloads over 1 MiB are rejected.

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for current status and planned improvements.

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
