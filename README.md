# 🥷🏼 PenTron
### AI-Powered Penetration Testing Assistant

<p align="center">
  <img width="524" height="161" alt="image" src="https://github.com/user-attachments/assets/1d9476ca-1fc8-4eec-940e-7fa41dd08ad3" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Runtime-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI-Qwen%203.5-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/DB-MariaDB-orange?style=for-the-badge&logo=mariadb"/>
  <img src="https://img.shields.io/badge/Web-FastAPI-teal?style=for-the-badge&logo=fastapi"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

---

> 🥷🏼 **Originally forked from** [METATRON](https://github.com/sooryathejas/METATRON) by [Soorya Thejas](https://github.com/sooryathejas) — credit for the core concept (local AI + real recon tools + agentic analysis loop) goes to the upstream project. PenTron has since been rewritten and expanded well past that starting point — roughly 2.6x the Python of the original alone, plus a full web app, Docker stack, and test suite that didn't exist upstream at all; see below for specifics.

## 🆕 What's different from the original METATRON

The original METATRON is a single ~2,000-line terminal script with a hardcoded local model, no web UI, no tests, and no target/scope enforcement beyond a tool-name allowlist. PenTron has grown into a packaged Python project (`pentron/`, installable console script) with a FastAPI web backend, a Dockerized stack, and a pytest suite — none of which exist upstream. On top of that foundation, it also adds:

- **Full Dockerization** — `docker compose up -d` brings up MariaDB, Ollama, and the app together, with the schema applied automatically. The original requires manually installing and configuring every dependency (MariaDB, Ollama, system packages) natively.
- **A full web UI** (FastAPI + HTMX + Tailwind) — the original has no browser interface at all. Start from an ops-console Overview, launch scans from a dedicated two-column workspace with a live command preview, watch progress (step tracker + per-tool checklist), browse/edit/delete history, and download reports. The terminal CLI still works unchanged, side by side.
- **Multi-provider AI** — the original is hardwired to one local Ollama model. This fork adds a provider abstraction (`providers.py`) supporting Ollama, OpenAI, Anthropic, and Google, switchable at runtime from the Settings screen — no code edit, no restart.
- **Runtime, database-backed settings** — provider, model, and timeouts are stored in a `settings` table and read fresh on every scan, instead of hardcoded constants in `llm.py`.
- **Four new security guards, none of which existed upstream:**
  - *Scope guard* — every `[TOOL:]` call the AI issues must have **every** positional argument match the declared session target; blocks both a pivot to a different host and a second target smuggled alongside the real one (`nmap target.com 10.0.0.5`).
  - *SSRF guard* — recon header fetches no longer auto-follow redirects; a redirect to a different host, or to a non-standard port on the *same* host, is blocked and reported instead of silently followed.
  - *Pre-flight private-target check* — before any recon runs, a domain whose DNS resolves to a private/loopback/internal address is refused outright, closing the gap where a target's own DNS could redirect a scan onto internal infrastructure.
  - *CVE citation check* — flags any CVE the AI cites in its findings that never actually appeared in the scan data, instead of trusting the citation at face value.
- **Configurable rate limiting + automatic retries** — an optional delay between recon tools (0 by default), set from the Settings screen, so a scan doesn't hit a small target with several tools back to back; short network-flaky tools (whois, curl headers, dig) auto-retry once on a timeout before giving up.
- **Configurable User-Agent** — override the HTTP User-Agent sent by curl/whatweb/nikto (e.g. to see how a target behaves for a browser vs. a tool that's WAF-signature-blocked by default). A fixed, operator-chosen value applied to every scan — deliberately **not** randomized or rotated per request, which would trade traceability for evasion.
- **Subdomain discovery (3 levels)** — the original only ever scans the exact declared target, missing `mail.`/`dev.`/`staging.` subdomains where real issues often live. Set from the Settings screen: disabled (default), passive (crt.sh certificate transparency — zero traffic to the target, listed in the report only), or active (crt.sh + subfinder — discovered subdomains also become valid scope-guard targets for that scan, so the AI can follow up on them). Passive never widens scope; only active does, and only for what it actually found.
- **Email-security DNS checks (SPF/DMARC/DKIM)** — `dig` now also queries `_dmarc.<target>` and `default._domainkey.<target>`, and the report explicitly flags SPF/DMARC/DKIM as present or missing (their absence is a real spoofing/phishing risk for the domain, not just a DNS curiosity). The DKIM check only tests the common `default` selector — its absence doesn't prove DKIM isn't configured under another selector, and the report says so.
- **WAF detection (wafw00f)** — a 9th, opt-in recon tool. A "clean" nikto/nmap pass behind an active WAF doesn't mean much on its own; knowing a WAF is there changes how the rest of the scan should be read. Checks both http and https in one pass.
- **robots.txt / security.txt check** — a 10th, opt-in recon tool. Fetches `robots.txt` (sometimes leaks paths an admin doesn't want indexed) and `security.txt` per RFC 9116 (checked at `/.well-known/security.txt`, falling back to the legacy root path) to see whether the target documents a vulnerability-disclosure process.
- **HTTP security header analysis** — `curl headers` now flags HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy as present or missing (checked on both http and https), instead of leaving the AI to spot their absence in a raw header dump.
- **GPU as an explicit, documented choice** — CPU-only by default so the stack runs anywhere out of the box, with a one-line Compose overlay (`docker-compose.gpu.yml`) to opt into GPU passthrough, and a live (read-only, not a toggle) GPU status indicator in the UI.


## 📌 What is PenTron?

**PenTron** is an AI penetration testing assistant that runs entirely on your own machine — no cloud dependency required, no subscriptions.

You give it a target IP or domain. It runs real recon tools (nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl.sh, wafw00f), feeds all results to an AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history.

Two ways to drive it:
- **Web UI** — an ops-console homepage plus dedicated New Scan, live progress, history, report, and provider-settings screens.
- **Terminal CLI** — an interactive menu in the same spirit as the original (New Scan / History / Settings), kept at full feature parity with the web UI rather than left as a legacy fallback.

Both talk to the exact same recon/AI/database engine, so scan history is shared between them.

---

## ✨ Features

- 🖥️ **Web ops console** — Overview homepage, dedicated New Scan workspace, live progress, history management, and report downloads
- 🤖 **Multi-provider AI** — Ollama (local, offline, default), OpenAI, Anthropic, or Google, switchable from the Settings screen with no restart
- 🔍 **Automated Recon** — nmap, whois, whatweb, curl headers, dig DNS, nikto, sslscan, testssl.sh (TLS/SSL config audit), wafw00f (WAF detection)
- 🌐 **Web Search** — DuckDuckGo search + CVE lookup (no API key needed)
- 🗄️ **MariaDB Backend** — full scan history with linked tables, shared between the web UI and the CLI
- ✏️ **Edit / Delete** — modify any saved result from either interface
- 🔁 **Agentic Loop** — AI can request more tool runs mid-analysis
- 📤 **Export Reports** — PDF and HTML, downloadable straight from the web UI or via the CLI
- 🛡️ **Scoped tool dispatch** — every `[TOOL:]` call the AI issues must have *every* positional argument match the operator-declared target; anything else (a pivot to another host, or a second target smuggled alongside the real one) is blocked and reported, not silently run
- ⏱️ **Rate limiting + retries** — optional delay between recon tools (Settings screen, default off) plus a single automatic retry on timeout for network-flaky tools (whois, curl headers, dig)
- 🪪 **Configurable User-Agent** — override the HTTP User-Agent for curl/whatweb/nikto from the Settings screen; a fixed value applied to every scan, not randomized
- 🌐 **Subdomain discovery (3 levels)** — disabled (default) / passive (crt.sh, informative only) / active (crt.sh + subfinder, discovered subdomains become scannable) — set from the Settings screen
- 📧 **SPF/DMARC/DKIM checks** — dig now flags missing email-security DNS records (spoofing/phishing risk), not just the raw A/MX/NS/TXT dump
- 🧱 **WAF detection (wafw00f)** — checks both http and https for a Web Application Firewall in front of the target, opt-in (custom tool selection)
- 📄 **robots.txt / security.txt check** — fetches both files (RFC 9116 path + legacy fallback) to spot leaked paths and check for a documented vulnerability-disclosure process
- 🔐 **HTTP security header analysis** — flags HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy as present or missing on both http and https
- 🔒 **Detection only, no exploitation** — `ALLOWED_TOOLS` is recon/fingerprinting tools only; the AI's `EXPLOIT:` suggestions are text proposals for a human to review, never code that gets run against the target
- 🔒 **SSRF-guarded recon** — header fetches don't blindly follow redirects onto localhost/internal services/cloud metadata, including same-host redirects to a different, non-standard port
- 🧭 **Pre-flight target check** — before any recon runs, a domain that resolves to a private/loopback/internal address is refused outright (its DNS could have been changed to redirect scans onto your own infrastructure); a literal IP typed directly by the operator is always allowed
- ✅ **CVE citation check** — a CVE the AI cites but that never appeared in the actual scan data is flagged `[UNVERIFIED CVE]` instead of trusted at face value

---

## 🖥️ Screenshots

<p align="center">
  <img width="736" height="347" alt="image" src="https://github.com/user-attachments/assets/056328f0-49c7-4dd1-9297-daabe3e736ee" />
  <br><i>Main Menu (CLI)</i>
</p>

<p align="center">
  <img width="748" height="724" alt="image" src="https://github.com/user-attachments/assets/a14c147d-d349-4086-a0ef-81b6c0c68cdb" />
  <br><i>Recon tools running on target (CLI)</i>
</p>

<p align="center">
  <img width="731" height="571" alt="image" src="https://github.com/user-attachments/assets/e1f2d2c2-69ed-4065-8665-36b5e751ed61" />
  <br><i>Settings (CLI)</i>
</p>

---

## 🧱 Tech Stack

| Component     | Technology                                          |
|---------------|------------------------------------------------------|
| Language      | Python 3.12+                                        |
| Web backend   | FastAPI + Uvicorn                                   |
| Web frontend  | Jinja2 + HTMX + Tailwind CSS                        |
| AI Providers  | Ollama (local), OpenAI, Anthropic, Google            |
| Default model | huihui_ai/qwen3.5-abliterated:9b via Ollama (optional custom-tuned alias via `Modelfile`) |
| Database      | MariaDB                                             |
| Containers    | Docker + Docker Compose (portable host; Kali Rolling container image) |
| Search        | DuckDuckGo (free, no key)                           |

---

## 🚀 Quick Start (Docker — recommended)

This is the fastest path and the only one that ships the web UI out of the box. It requires [Docker](https://docs.docker.com/get-docker/) and Docker Compose, but no particular host distribution: Linux, macOS, and Windows with Docker Desktop are supported. Kali Rolling is used only inside the application container because it provides the recon-tool packages PenTron needs; the host itself does not need to run Kali or Parrot.

```bash
git clone https://github.com/SaiedZ/PenTron.git
cd PenTron
docker compose up -d
```

This starts three services: `mariadb` (database, schema applied automatically), `ollama` (local AI runtime, CPU by default), and `web` (the browser dashboard). Open:

```
http://localhost:8000
```

> **Windows:** this whole stack runs fine on Windows too — install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (WSL2 backend) and run the same `docker compose up -d` from PowerShell or a WSL shell. The recon tools (nmap, nikto, etc.) run inside the Linux container regardless of host OS, so there's nothing extra to install natively. This is also the easiest way to run PenTron if your machine doesn't have the RAM/disk for a local Ollama model — point `OLLAMA_HOST` at a remote Ollama instance, or use a hosted provider (OpenAI/Anthropic/Google) from the Settings screen instead.

If you'd rather use the terminal menu instead of (or alongside) the web UI, it's still there as a fourth service:

```bash
docker compose run --rm pentron
```

### Loading a model into Ollama

The web UI's Settings screen can list models already pulled into Ollama and let you pick one. Pull the default model — this alone is enough to start scanning, no extra step needed:

```bash
docker exec -it pentron-ollama ollama pull huihui_ai/qwen3.5-abliterated:9b
```

Optionally, build a custom-tuned alias with this repo's `Modelfile` (16k context window, temperature 0.7, etc. — see [Modelfile](Modelfile)) and select it from Settings instead:

```bash
docker cp Modelfile pentron-ollama:/Modelfile
docker exec -it pentron-ollama ollama create pentron-qwen -f /Modelfile
```

Or skip Ollama entirely and pick OpenAI / Anthropic / Google from Settings instead — paste an API key and you're set, no local model or GPU needed.

### GPU acceleration for Ollama

Ollama runs on CPU by default so the stack works out of the box on any machine. To pass an NVIDIA GPU through to it, layer the GPU overlay on top of the base Compose file instead of editing it:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d ollama
```

Requires the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) installed on the host.

> ⚠️ **Include `-f docker-compose.gpu.yml` on every `docker compose up` after this**, not just the first time — Compose reconciles services from whatever files you pass *that invocation*, so a plain `docker compose up -d` (without the GPU file) will silently recreate `ollama` back to CPU-only, even if GPU was active before. Rebuilding or restarting the `web` service specifically does not affect `ollama`, so it's safe on its own — it's a bare `docker compose up`/`up web`/etc. *without* `-f docker-compose.gpu.yml` that resets it.
>
> To avoid typing both `-f` flags every time, drop a `.env` file in the project root with:
> ```
> COMPOSE_FILE=docker-compose.yml;docker-compose.gpu.yml
> ```
> (use `:` instead of `;` as the separator on Linux/macOS). Docker Compose reads this automatically, so a plain `docker compose up -d` will always include the GPU overlay.
>
> The Settings screen shows a **live, read-only** GPU status badge (queried from Ollama, not a toggle) — it can only report "unknown" if no model is currently loaded into Ollama to check.

### Restarting a service while a scan is running

Avoid rebuilding or restarting the `web` service while a scan is actively in progress (visible via its live progress page) — it runs in a background thread inside that container, so replacing the container kills it mid-flight. Recon tools are all read-only, so nothing unsafe happens; you'll just need to relaunch the scan.

---

## 🛠️ Native installation (alternative)

Docker is the recommended setup. To run PenTron directly on the host, follow
the [native installation guide](docs/native-installation.md) for Python 3.12,
recon tools, Ollama, MariaDB, and the native web UI.

## 🚀 Usage

### Web UI

1. Open `http://localhost:8000` (or wherever `uvicorn api.main:app` is listening for a native install). The **Overview** homepage introduces the recon-to-report workflow and provides shortcuts to the main screens.
2. Open **New Scan** (`/new-scan`), enter an authorized target, choose a preset or custom set of recon tools, select the subdomain-discovery level, and review the live command preview before submitting.
3. You're redirected to a live progress page that polls automatically — a step tracker (Recon → AI Analysis → Saving → Done), a checklist of planned vs. completed recon tools, then AI analysis round N of 9, plus anything the scope/SSRF guards blocked along the way.
4. Once done, jump to the session's detail page: vulnerabilities, fixes, and exploit attempts, each editable or deletable inline, plus **Download PDF** / **Download HTML** buttons.
5. **History** lists every past session (shared with the CLI); **Settings** configures the AI provider/model, timeouts, and shows live GPU status. The persistent navigation links Overview, New Scan, History, and Settings.

### Terminal CLI

PenTron's CLI needs the AI model loaded and reachable, and MariaDB running — both handled automatically if you're on Docker (`docker compose run --rm pentron` waits for both).

**1. Main menu appears:**
```
  [1]  New Scan
  [2]  View History
  [3]  Exit
```

**2. Select [1] New Scan → enter your target:**
```
[?] Enter target IP or domain: 192.168.1.1
```
or
```
[?] Enter target IP or domain: example.com
```

**3. Select recon tools to run:**
```
  [1] nmap
  [2] whois
  [3] whatweb
  [4] curl headers
  [5] dig DNS
  [6] nikto
  [7] sslscan
  [8] testssl.sh
  [9] wafw00f
  [10] robots/security.txt
  [a] Run all (except nikto, sslscan, testssl.sh, wafw00f, robots/security.txt)
  [n] Run all + nikto (slow)
```

**4. PenTron runs the tools, feeds results to the AI, and prints the analysis.**

**5. Everything is saved to MariaDB automatically — visible from the web UI too.**

**6. After the scan you can edit or delete any result.**

---

## 📁 Project Structure

```
PenTron/
├── pentron/                 ← core package (console script: `pentron`)
│   ├── cli.py                 ← CLI entry point (pentron.cli:main)
│   ├── db.py                   ← MariaDB connection and all CRUD operations
│   ├── tools/                   ← recon tool runners, one file per tool + a
│   │                                decorator-based registry (nmap, whois, ...)
│   ├── llm.py                    ← AI provider interface and tool dispatch loop
│   ├── providers.py               ← LLM provider abstraction (Ollama/OpenAI/Anthropic/Google)
│   ├── search.py                   ← DuckDuckGo web search and CVE lookup
│   └── export/                      ← PDF/HTML report generation, CLI export menu
├── api/                     ← FastAPI web backend
│   ├── main.py               ← app entry point (uvicorn api.main:app)
│   ├── jobs.py                ← live scan-progress tracking
│   ├── scan_runner.py          ← background scan pipeline (web UI's New Scan)
│   ├── schemas.py               ← request/response models
│   ├── serializers.py            ← DB row → JSON mapping
│   ├── security.py                ← optional shared-secret API auth
│   └── routers/                    ← scans / history / exports / settings / pages
├── web/                     ← web UI assets
│   ├── templates/             ← Jinja2 + HTMX pages
│   │   ├── home.html            ← Overview homepage (/)
│   │   ├── dashboard.html       ← New Scan form (/new-scan)
│   │   ├── scan_progress.html   ← live scan progress
│   │   ├── history_list.html    ← saved sessions
│   │   ├── session_detail.html  ← findings and report detail
│   │   └── settings.html        ← provider and scan settings
│   ├── static/                  ← compiled Tailwind CSS + JS
│   ├── input.css                 ← Tailwind source
├── Modelfile               ← optional custom-tuned model alias (see native guide)
├── Dockerfile               ← Kali Rolling image (recon tools + Tailwind build)
├── docker-compose.yml       ← mariadb + ollama + web + pentron (CLI) services
├── docker-compose.gpu.yml   ← GPU overlay for the ollama service
├── docker/
│   ├── schema.sql             ← full DB schema, auto-applied on first start
│   └── entrypoint.sh            ← waits for MariaDB/Ollama before launching
├── docs/
│   └── native-installation.md ← native setup without Docker
├── pyproject.toml           ← Python deps (runtime + optional [dev]/[test]), ruff/mypy config
├── uv.lock                  ← locked transitive dependency versions (re-run `uv lock` after editing pyproject.toml)
├── .gitignore                ← excludes venv, pycache, generated CSS, db files
├── LICENSE                   ← MIT License
└── README.md                  ← this file
```

---

## 🗃️ Database Schema

Six tables, five of them linked by `sl_no` (session number) from the `history` table; `settings` is a standalone single-row table for runtime configuration:

```
history              ← one row per scan session (sl_no is the spine)
    │
    ├── vulnerabilities   ← vulns found, linked by sl_no
    │       │
    │       └── fixes     ← fixes per vuln, linked by vuln_id + sl_no
    │
    ├── exploits_attempted ← exploits tried, linked by sl_no
    │
    └── summary           ← full AI analysis dump, linked by sl_no

settings              ← single row: active provider, model, timeouts, API key
                         (read/written by the web UI's Settings screen)
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.

- Only use PenTron on systems you own or have **explicit written permission** to test.
- Unauthorized scanning or exploitation of systems is **illegal**.
- The author is not responsible for any misuse of this tool.
- A domain that resolves to a private/loopback/internal address is refused automatically (see Features) — if you're intentionally testing your own local network, enter the IP address directly rather than a hostname.
- **Detection only, by design — there is no "safe mode" toggle because there is no unsafe mode to disable.** `ALLOWED_TOOLS` contains only recon/fingerprinting tools (nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl, wafw00f) — no exploitation framework (no Metasploit, sqlmap, hydra, etc.) is ever invoked. The `EXPLOIT:` entries you see in a session's results are the AI's own text suggestions parsed from its analysis — proposed exploit ideas for a human to review, never executed against the target.

---

## 👤 Author

**SaiedZ**
- GitHub: [@SaiedZ](https://github.com/SaiedZ)

Originally forked from [METATRON](https://github.com/sooryathejas/METATRON) by [Soorya Thejas](https://github.com/sooryathejas).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
