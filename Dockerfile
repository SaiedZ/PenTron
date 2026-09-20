# PENTRON - AI Penetration Testing Assistant
# Kali Rolling is an implementation detail of the container image: it provides
# the recon tools the app expects, while the host can run any Docker-supported OS.

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Pin to a plain-HTTP mirror: the default geoip redirector sometimes hands out
# an HTTPS mirror with a broken cert chain (network-dependent), which breaks apt.
RUN rm -f /etc/apt/sources.list.d/kali.sources && \
    echo "deb http://kali.download/kali kali-rolling main non-free non-free-firmware contrib" \
    > /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        whois \
        whatweb \
        curl \
        dnsutils \
        nikto \
        sslscan \
        testssl.sh \
        subfinder \
        wafw00f \
        wpscan \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Static, self-contained binary — no separate install step needed.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Two-phase sync, same trick a `COPY requirements.txt .` + `pip install`
# split was doing: install dependencies from the lockfile first (cached as
# long as pyproject.toml/uv.lock don't change), then install the project
# itself once the full source is copied in below. uv installs into its own
# venv (/app/.venv), fully isolated from apt's system Python packages (e.g.
# wafw00f's Debian-packaged requests/urllib3) — unlike the old
# --break-system-packages pip install, there's no risk of collision so no
# --ignore-installed workaround is needed either.
# Re-run `uv lock` locally after editing pyproject.toml's dependencies.
COPY pyproject.toml uv.lock .
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

ENV PATH="/app/.venv/bin:$PATH"

RUN chmod +x /app/docker/entrypoint.sh

# Compile the web UI's stylesheet with Tailwind's standalone CLI (a
# self-contained binary, no Node/npm) — ships a real, purged production
# stylesheet instead of the Play CDN script Tailwind doesn't recommend
# for production. One-shot build step, the binary isn't needed at runtime.
RUN curl -sLo /usr/local/bin/tailwindcss \
        https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss -i web/input.css -o web/static/css/tailwind.css --minify \
    && rm /usr/local/bin/tailwindcss

RUN mkdir -p /app/exports

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["pentron"]
