# Native installation

Docker is the recommended way to run PenTron. This guide covers the alternative
setup where Python, the recon tools, Ollama, and MariaDB run directly on the
host.

## Requirements

- Python 3.12 or newer
- MariaDB
- The recon tools listed below
- Ollama, unless you use a hosted AI provider
- The Tailwind standalone CLI if you run the web UI

The commands below target Debian-based Linux distributions. Package names and
service-management commands may differ on other operating systems.

## 1. Clone the repository

```bash
git clone https://github.com/SaiedZ/PenTron.git
cd PenTron
```

## 2. Install Python dependencies

PenTron uses [`uv`](https://docs.astral.sh/uv/) to create `.venv` and install
the versions from the committed `uv.lock`:

```bash
uv sync
```

For development tools such as pytest, Ruff, and mypy:

```bash
uv sync --extra dev
```

Activate the environment with `source .venv/bin/activate`, or prefix commands
with `uv run`.

Without `uv`, use:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Use `pip install -e ".[dev]"` to include development tools. The editable
install is important because the web app resolves its templates and static
files relative to the repository.

## 3. Install the recon tools

On a Debian-based distribution:

```bash
sudo apt install nmap whois whatweb curl dnsutils nikto sslscan testssl.sh subfinder wafw00f wpscan
```

`subfinder` is only required for active subdomain discovery (level 2), which is
disabled by default.

WPScan is opt-in and runs only when another selected recon module first detects
WordPress. Its command is fixed to vulnerable plugins and themes (`vp,vt`) in
passive detection mode; user enumeration and password attacks are never run.
Set `WPSCAN_API_TOKEN` in the runtime environment if vulnerability details are
required from the WPScan API.

## 4. Configure the AI provider

### Local Ollama

Install Ollama and pull PenTron's default model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull huihui_ai/qwen3.5-abliterated:9b
```

This model requires at least 8.4 GB of RAM. On a smaller machine, use the 4b
variant and select it from Settings (or set `PENTRON_MODEL`):

```bash
ollama pull huihui_ai/qwen3.5-abliterated:4b
```

Optionally create the custom-tuned alias defined by the repository's
[`Modelfile`](../Modelfile):

```bash
ollama create pentron-qwen -f Modelfile
```

Select `pentron-qwen` from Settings afterward; it is not selected automatically.
Run `ollama list` to verify which models are available.

### Hosted provider

To use OpenAI, Anthropic, or Google, skip Ollama and configure the provider and
API key from the web UI's Settings screen or through environment variables.

## 5. Configure MariaDB

Start MariaDB:

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

Create the database and user:

```bash
mysql -u root
```

```sql
CREATE DATABASE pentron;
CREATE USER 'pentron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON pentron.* TO 'pentron'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Create the tables from the repository root:

```bash
mysql -u pentron -p123 pentron < docker/schema.sql
```

## 6. Run PenTron

Start the terminal interface:

```bash
uv run pentron
```

For the web UI, install the
[Tailwind standalone CLI](https://tailwindcss.com/blog/standalone-cli), compile
the stylesheet, and start FastAPI:

```bash
tailwindcss -i web/input.css -o web/static/css/tailwind.css --minify
uv run uvicorn api.main:app
```

Open `http://localhost:8000`.
