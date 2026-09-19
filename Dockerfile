# PENTRON - AI Penetration Testing Assistant
# Base image: Kali Rolling, so nmap/whois/whatweb/nikto etc. match the
# tools the app expects (originally built for Parrot OS).

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
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# --ignore-installed: wafw00f pulls in python3-urllib3/requests/certifi/idna
# as Debian-packaged apt dependencies (no RECORD file), which pip can't
# uninstall to replace with the pinned versions below — shadow them instead
# of failing the build trying to remove them.
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt

COPY . .

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
CMD ["python3", "pentron.py"]
