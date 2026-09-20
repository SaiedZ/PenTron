# Optional NVIDIA GPU acceleration

Ollama runs on CPU by default so the stack works out of the box on any
machine. This guide covers passing an NVIDIA GPU through to it.

## Enabling the GPU overlay

Layer the GPU overlay on top of the base Compose file instead of editing it:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d ollama
```

Requires the [NVIDIA Container
Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
installed on the host.

For development with GPU acceleration, include the dev overlay too:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.dev.yml up
```

## Keep including the overlay on every `up`

⚠️ **Include `-f docker-compose.gpu.yml` on every `docker compose up` after
this**, not just the first time — Compose reconciles services from whatever
files you pass *that invocation*, so a plain `docker compose up -d` (without
the GPU file) will silently recreate `ollama` back to CPU-only, even if GPU
was active before. Rebuilding or restarting the `web` service specifically
does not affect `ollama`, so it's safe on its own — it's a bare `docker
compose up`/`up web`/etc. *without* `-f docker-compose.gpu.yml` that resets
it.

To avoid typing both `-f` flags every time, drop a `.env` file in the
project root with:

```
COMPOSE_FILE=docker-compose.yml;docker-compose.gpu.yml
```

(use `:` instead of `;` as the separator on Linux/macOS). Docker Compose
reads this automatically, so a plain `docker compose up -d` will always
include the GPU overlay.

## Checking GPU status

The Settings screen shows a **live, read-only** GPU status badge (queried
from Ollama, not a toggle) — it can only report "unknown" if no model is
currently loaded into Ollama to check.
