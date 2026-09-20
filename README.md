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

> PenTron was originally inspired by [METATRON](https://github.com/sooryathejas/METATRON) by [Soorya Thejas](https://github.com/sooryathejas), particularly its core idea of combining local AI with real reconnaissance tools.
>
> PenTron has since evolved into an independent project with its own architecture, web interface, CLI, multi-provider AI pipeline, structured analysis, security controls, persistence layer, Docker stack, exports, and automated test suite.

## 📌 What is PenTron?

**PenTron** is an AI penetration testing assistant that can run entirely on your own machine with Ollama, without a cloud dependency or subscription. OpenAI, Anthropic, and Google are also supported as optional providers.

You give it a target IP or domain. It runs real recon tools (nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl.sh, wafw00f), feeds all results to an AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history.

Two ways to drive it:
- **Web UI** — an ops-console homepage plus dedicated New Scan, live progress, history, report, and provider-settings screens. Also the only interface with the contextual AI chat and JSON export.
- **Terminal CLI** — an interactive menu in the same spirit as the original (New Scan / History / Settings).

Both interfaces share the same scanning, AI, and database engine, so scan history is shared between them — but they aren't full feature parity: the contextual chat and JSON export are web-only for now.

---

## ✨ Features

- 🖥️ **Web ops console** — Overview homepage, dedicated New Scan workspace, live progress, history management, and report downloads
- 🤖 **Multi-provider AI** — Ollama (local, offline, default), OpenAI, Anthropic, or Google, switchable from the Settings screen with no restart
- ✅ **Validated AI reports** — large recon outputs are condensed per tool and final assessments are validated as structured data; malformed or truncated responses are preserved as partial scans instead of false successes
- 📊 **Readable, traceable results** — short summary, safely rendered Markdown report, severity distribution, structured findings and fixes, suggested exploit paths, and separately logged AI-dispatched tool calls
- 🔍 **Automated Recon** — nmap, whois, whatweb, curl headers, dig DNS, nikto, sslscan, testssl.sh (TLS/SSL config audit), wafw00f (WAF detection), and opt-in conditional WPScan
- 🌐 **Web Search** — DuckDuckGo search + CVE lookup (no API key needed)
- 🗄️ **MariaDB Backend** — full scan history with linked tables, shared between the web UI and the CLI
- ✏️ **Edit / Delete** — modify saved vulnerabilities, fixes, and the risk level from either interface
- 💬 **Contextual AI chat (web only)** — ask follow-up questions about a specific scan session; the AI answers from that session's findings and summary only (not the raw recon output), with older turns automatically summarized once the conversation grows long
- 🔁 **Agentic Loop** — AI can request more tool runs mid-analysis
- 📤 **Export Reports** — PDF and HTML from either interface; the web UI also offers JSON (optionally including raw scan data)
- 🛡️ **Scoped tool dispatch** — every `[TOOL:]` call the AI issues must have *every* positional argument match the operator-declared target; anything else (a pivot to another host, or a second target smuggled alongside the real one) is blocked and reported, not silently run
- ⏱️ **Rate limiting + retries** — optional delay between recon tools (Settings screen, default off) plus a single automatic retry on timeout for network-flaky tools (whois, curl headers, dig)
- 🪪 **Configurable User-Agent** — override the HTTP User-Agent for curl/whatweb/nikto from the Settings screen; a fixed value applied to every scan, not randomized
- 🌐 **Subdomain discovery (3 levels)** — disabled (default) / passive (crt.sh, informative only) / active (crt.sh + subfinder, discovered subdomains become scannable) — set from the Settings screen
- 📧 **SPF/DMARC/DKIM checks** — dig now flags missing email-security DNS records (spoofing/phishing risk), not just the raw A/MX/NS/TXT dump
- 🧱 **WAF detection (wafw00f)** — checks both http and https for a Web Application Firewall in front of the target, opt-in (custom tool selection)
- 📄 **robots.txt / security.txt check** — fetches both files (RFC 9116 path + legacy fallback) to spot leaked paths and check for a documented vulnerability-disclosure process
- 🔐 **HTTP security header analysis** — flags HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy as present or missing on both http and https
- 🔒 **Detection only, no exploitation** — allowed tools are limited to reconnaissance and fingerprinting; suggested exploit paths remain proposals for human review and are never executed automatically
- 🔒 **SSRF-guarded recon** — header fetches don't blindly follow redirects onto localhost/internal services/cloud metadata, including same-host redirects to a different, non-standard port
- 🧭 **Pre-flight target check** — before any recon runs, a domain that resolves to a private/loopback/internal address is refused outright (its DNS could have been changed to redirect scans onto your own infrastructure); a literal IP typed directly by the operator is always allowed
- ✅ **CVE citation check** — a CVE the AI cites but that never appeared in the actual scan data is flagged `[UNVERIFIED CVE]` instead of trusted at face value

---

## 🖥️ Screenshots

### Terminal CLI

#### Interactive main menu

<p align="center">
  <img width="736" height="347" alt="image" src="https://github.com/user-attachments/assets/056328f0-49c7-4dd1-9297-daabe3e736ee" />
  <br><i>Main Menu</i>
</p>

#### Recon tools running

<p align="center">
  <img width="748" height="724" alt="image" src="https://github.com/user-attachments/assets/a14c147d-d349-4086-a0ef-81b6c0c68cdb" />
  <br><i>Recon tools running on target</i>
</p>

### Web UI

#### New scan configuration

<p align="center">
  <!-- Add the New Scan configuration <img> here. -->
  <br><i>New scan configuration — target definition, recon tool selection, subdomain discovery, and live command preview.</i>
</p>

#### Live scan progress

<p align="center">
  <img width="1269" height="716" alt="image" src="https://github.com/user-attachments/assets/f64b4c42-fa0c-4a01-ae10-2f10dc28600a" />
  <br><i>Live scan progress — real-time recon tracking, tool-by-tool execution, and automatic transition to AI analysis.</i>
</p>

#### Structured scan results

<p align="center">
  <img width="1251" height="807" alt="image" src="https://github.com/user-attachments/assets/3e296b39-b335-421f-83c3-aa8b28792a02" />
  <br><i>Structured scan results — validated risk level, severity distribution, findings, remediation guidance, and traceable AI analysis.</i>
</p>

#### Contextual AI chat

<p align="center">
  <!-- Add the contextual AI chat <img> here. -->
  <br><i>Contextual AI chat — ask follow-up questions about a session's findings, backed by a concise, session-specific security context (not the raw recon output).</i>
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

### First installation

Clone the repository and start the application services:

```bash
git clone https://github.com/SaiedZ/PenTron.git
cd PenTron
docker compose up -d
```

This starts three services: `mariadb` (database, schema applied automatically), `ollama` (local AI runtime, CPU by default), and `web` (the browser dashboard).

Docker starts Ollama, but **does not download the AI model automatically**. Before running your first scan, pull the default model (the download is several GB and may take a while):

```bash
docker exec -it pentron-ollama ollama pull huihui_ai/qwen3.5-abliterated:9b
```

When the download is complete, open:

```
http://localhost:8000
```

The model is stored in the persistent Docker volume `ollama_data`, so this download is only required once. You can confirm that it is installed with:

```bash
docker exec pentron-ollama ollama list
```

> **Windows:** this whole stack runs fine on Windows too — install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (WSL2 backend) and run the same `docker compose up -d` from PowerShell or a WSL shell. The recon tools (nmap, nikto, etc.) run inside the Linux container regardless of host OS, so there's nothing extra to install natively. This is also the easiest way to run PenTron if your machine doesn't have the RAM/disk for a local Ollama model — point `OLLAMA_HOST` at a remote Ollama instance, or use a hosted provider (OpenAI/Anthropic/Google) from the Settings screen instead.

> PenTron works on CPU by default. If you have a compatible NVIDIA GPU, see [Optional NVIDIA GPU acceleration](#optional-nvidia-gpu-acceleration) before running your first scan.

### Starting and stopping PenTron later

For subsequent starts, the model is already available, so only run:

```bash
docker compose up -d
```

To stop the application:

```bash
docker compose down
```

> Do not add `-v` unless you intentionally want to delete PenTron's persistent data, including the downloaded Ollama model and the database volume.

If you'd rather use the terminal menu instead of (or alongside) the web UI, start it after the services are running:

```bash
docker compose run --rm pentron
```

### Development with automatic reload

The production image contains a copy of the source code, so ordinary local changes are not visible inside the container. During development, layer the development Compose file on top of the standard configuration:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

This mounts `api/`, `pentron/`, the web templates, and JavaScript files into the `web` container. Uvicorn automatically reloads after Python changes; template and JavaScript changes are available after refreshing the browser. MariaDB and Ollama keep running normally.

For development with NVIDIA GPU acceleration, include both optional overlays:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.dev.yml up
```

Changes to dependencies (`pyproject.toml` or `uv.lock`), the `Dockerfile`, or installed system tools still require an image rebuild. Rebuild only the web service without restarting MariaDB or Ollama:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build web
```

The generated Tailwind stylesheet is still a build artifact. Changes to `web/input.css`, or template changes that introduce Tailwind classes not already present in the compiled stylesheet, also require rebuilding the CSS/image.

> An automatic Uvicorn reload restarts the web process. Do not edit reload-watched Python files while a scan is running, because its in-memory background job will be interrupted.

### Choosing another AI model or provider

The web UI's Settings screen lists models already pulled into Ollama and lets you select one. To use another Ollama model, pull it first with `docker exec -it pentron-ollama ollama pull <model-name>`, then select it in Settings.

Optionally, build a custom-tuned alias with this repo's `Modelfile` (16k context window, temperature 0.7, etc. — see [Modelfile](Modelfile)) and select it from Settings instead:

```bash
docker cp Modelfile pentron-ollama:/Modelfile
docker exec -it pentron-ollama ollama create pentron-qwen -f /Modelfile
```

Or skip Ollama entirely and pick OpenAI / Anthropic / Google from Settings instead — paste an API key and you're set, no local model or GPU needed.

### Optional NVIDIA GPU acceleration

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

### Troubleshooting Ollama

If a scan reports `Ollama HTTP error: 404 ... /api/chat`, Docker and Ollama may both be running correctly while the selected model is missing. Check the installed models:

```bash
docker exec pentron-ollama ollama list
```

If the list is empty, install the default model:

```bash
docker exec -it pentron-ollama ollama pull huihui_ai/qwen3.5-abliterated:9b
```

To check whether all application containers are running:

```bash
docker compose ps
```

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
4. Once done, jump to the session's detail page: vulnerabilities and fixes, each editable or deletable inline; a contextual AI chat to ask follow-up questions about that session's findings; and **Download PDF** / **Download HTML** / **Download JSON** buttons (JSON can optionally include the raw scan data).
5. **History** lists every past session (shared with the CLI); **Settings** configures the AI provider/model, timeouts, and shows live GPU status. The persistent navigation links Overview, New Scan, History, and Settings.

### Terminal CLI

PenTron's CLI needs the AI model loaded and reachable, and MariaDB running — both handled automatically if you're on Docker (`docker compose run --rm pentron` waits for both).

**1. Main menu appears:**
```
  [1]  New Scan
  [2]  View History
  [3]  Settings
  [4]  Exit
```

**2. Configure the CLI if needed:**

The **Settings** menu controls the AI provider, Ollama host or provider API key, model, AI timeouts, delay between recon tools, HTTP User-Agent, and subdomain-discovery level. Changes apply to the next scan without a restart; press **Enter** at the field prompt to return to the main menu.

**3. Select [1] New Scan → enter your target:**
```
[?] Enter target IP or domain: 192.168.1.1
```
or
```
[?] Enter target IP or domain: example.com
```

**4. Select recon tools to run:**
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
  [11] wpscan (only after another selected tool detects WordPress)
  [a] Run all (except nikto, sslscan, testssl.sh, wafw00f, robots/security.txt, wpscan)
  [n] Run all + nikto (slow)
```

Enter one or more tool numbers separated by spaces (for example, `1 2 4`), or use one of the `a` / `n` presets.

**5. PenTron runs the tools, feeds results to the AI, and prints the analysis.**

**6. Everything is saved to MariaDB automatically — visible from the web UI too.**

**7. Use View History to reopen and manage a session.**

Enter a session's SL# to view it, or press **Enter** to go back. From a session you can export PDF, HTML, or both; edit vulnerabilities, fixes, and the risk level; delete individual results; or delete the full session. Destructive actions require confirmation.

---

## 📁 Project Structure

```
PenTron/
├── pentron/              # Core scanning, AI analysis, contextual chat, and exports
│   ├── tools/            # Reconnaissance and security tool integrations
│   └── export/           # PDF, HTML, and JSON report generation
├── api/                  # FastAPI backend, routes, and background scan jobs
├── web/                  # Jinja2/HTMX interface and browser-side assets
├── tests/                # Automated test suite
├── docker/               # Database schema and container initialization
├── docs/                 # Additional installation and technical documentation
├── docker-compose.yml    # Main Docker deployment
├── pyproject.toml        # Python dependencies and project configuration
└── README.md
```

---

## 🗃️ Database Schema

Seven tables, six of them linked by `sl_no` (session number) from the `history` table; `settings` is a standalone single-row table for runtime configuration. Source of truth: [`docker/schema.sql`](docker/schema.sql) — update this diagram if it drifts.

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

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.

- Only use PenTron on systems you own or have **explicit written permission** to test.
- Unauthorized scanning or exploitation of systems is **illegal**.
- The author is not responsible for any misuse of this tool.
- A domain that resolves to a private/loopback/internal address is refused automatically (see Features) — if you're intentionally testing your own local network, enter the IP address directly rather than a hostname.
- **Detection only, by design — there is no "safe mode" toggle because there is no unsafe mode to disable.** `ALLOWED_TOOLS` contains only recon/fingerprinting tools (nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl, wafw00f) — no exploitation framework (no Metasploit, sqlmap, hydra, etc.) is ever invoked. WPScan is never AI-dispatchable: its opt-in command is fixed to passive enumeration of vulnerable plugins and themes (`vp,vt`), runs only after WordPress evidence, and includes no user or credential options. The exploit suggestions you see in a session's results are the AI's own structured proposals from its analysis — proposed exploit ideas for a human to review, never executed against the target.

---

## 👤 Author

**SaiedZ**
- GitHub: [@SaiedZ](https://github.com/SaiedZ)

Originally forked from [METATRON](https://github.com/sooryathejas/METATRON) by [Soorya Thejas](https://github.com/sooryathejas).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
