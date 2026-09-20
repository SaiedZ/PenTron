# Changelog

## v0.1.0 — first release

**PenTron** is a local-first AI penetration testing assistant. It runs real reconnaissance tools against a target, feeds the results to an AI model, and turns them into structured vulnerability findings, suggested exploit paths, and remediation guidance — all without a cloud dependency by default.

This is the project's first tagged release. PenTron started as a fork of [METATRON](https://github.com/sooryathejas/METATRON) by [Soorya Thejas](https://github.com/sooryathejas) and has since grown into an independent project with its own architecture, web UI, CLI, multi-provider AI pipeline, security controls, and test suite.

### Highlights

- 🔒 **Detection only, no exploitation** — allowed tools are limited to reconnaissance and fingerprinting; the AI only proposes exploit ideas for human review, nothing is executed automatically
- 🖥️ **Web ops console** (FastAPI + HTMX) — New Scan, live progress, history, reports, and provider settings
- 💻 **Terminal CLI** sharing the same scanning/AI/database engine as the web UI, with shared scan history
- 🤖 **Multi-provider AI** — Ollama (local, offline, default), OpenAI, Anthropic, or Google, switchable without a restart
- 🔍 **Automated recon** — nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl.sh, wafw00f, robots.txt/security.txt, opt-in WPScan, plus subdomain discovery (crt.sh / subfinder)
- 🗄️ **MariaDB-backed history** — every session persisted and browsable from either interface
- 💬 **Contextual AI chat** on a scan session's findings (web only)
- 📤 **PDF / HTML / JSON exports**
- 🛡️ **Security safeguards** — scoped `[TOOL:]` dispatch, SSRF-guarded recon, pre-flight target check, CVE citation verification, rate limiting

### Installation

Docker is the recommended path:

```bash
git clone https://github.com/SaiedZ/PenTron.git
cd PenTron
docker compose up -d
docker exec -it pentron-ollama ollama pull huihui_ai/qwen3.5-abliterated:9b
```

Then open `http://localhost:8000`. See the [README](README.md) for native installation, GPU acceleration, and full usage instructions.

### Known limitations

- Contextual AI chat and JSON export are web-only for now; not yet in the CLI
- Ollama runs on CPU by default — NVIDIA GPU acceleration is opt-in

### Disclaimer

For educational purposes and authorized penetration testing only — only use PenTron on systems you own or have explicit written permission to test. See the README's [Disclaimer](README.md#-disclaimer) section for full terms.
