# syntax=docker/dockerfile:1
# ============================================================================
# HexStrike AI MCP Agents v6.0 — container image (FULL ARSENAL)
#
# Base: Kali Rolling. Image ini memasang SEMUA tool & package yang di-probe
# oleh endpoint /health di hexstrike_server.py, dari berbagai sumber:
#   - apt (repo Kali)            -> mayoritas tool CLI security
#   - go install                 -> tool ProjectDiscovery & tomnomnom
#   - cargo                      -> x8, pwninit
#   - gem                        -> one_gadget
#   - pip / pipx (venv)          -> framework deps + tool berbasis Python
#   - git + build                -> libc-database, hashpump, docker-bench
#   - installer resmi            -> trivy, kube-bench, kube-hunter, terrascan
#
# CATATAN UKURAN: image ini SANGAT besar (belasan GB) karena memasang
# metapackage kali-linux-headless + toolchain (Go/Rust/Ruby) + Ghidra dll.
# Itu konsekuensi dari "pasang semua tool".
#
# Yang di-expose: Flask API server (hexstrike_server.py) di port 8888.
# ============================================================================
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="hexstrike-ai" \
      org.opencontainers.image.source="https://github.com/0x4m4/hexstrike-ai" \
      org.opencontainers.image.description="HexStrike AI MCP server (Flask API + full 150+ security tool arsenal)"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    GOPATH=/root/go \
    CARGO_HOME=/root/.cargo \
    PATH="/opt/venv/bin:/root/.local/bin:/root/.cargo/bin:/usr/local/go/bin:/root/go/bin:/opt/tools/bin:$PATH"

# Kali memakai mirror redirector http.kali.org yang tidak andal via https, dan
# base image belum punya ca-certificates. Firewall subnet memblok http, jadi:
#   1) arahkan semua sumber Kali ke CDN resmi https://kali.download
#   2) bootstrap ca-certificates via https (verify sementara off) supaya https tervalidasi
RUN find /etc/apt -type f \( -name "*.list" -o -name "*.sources" \) -exec sed -i \
        -e 's|http://http.kali.org/kali|https://kali.download/kali|g' \
        -e 's|https://http.kali.org/kali|https://kali.download/kali|g' \
        -e 's|http://kali.download/kali|https://kali.download/kali|g' \
        -e 's|http://|https://|g' {} + \
    && apt-get -o Acquire::https::Verify-Peer=false update \
    && apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 1) System deps + toolchain (build-essential, Go/Rust/Ruby, pipx, chromium)
#    Dibutuhkan oleh angr, pwntools, mitmproxy, cargo builds, dll.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-venv python3-pip pipx \
        build-essential pkg-config git curl wget unzip ca-certificates gnupg \
        libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev \
        ruby ruby-dev rustc cargo \
        chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2) Full Kali arsenal (metapackage) + tool-tool eksplisit yang di-probe /health
#    kali-linux-headless sudah membawa mayoritas tool CLI; sisanya kita
#    tambahkan eksplisit agar coverage lengkap.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        kali-linux-headless \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
        # --- essential / recon / network ---
        nmap masscan rustscan dnsenum dnsrecon amass theharvester whatweb wafw00f \
        nbtscan arp-scan responder netexec crackmapexec enum4linux enum4linux-ng \
        smbclient smbmap onesixtyone snmp \
        # --- web app ---
        gobuster feroxbuster ffuf dirb dirsearch nikto sqlmap wpscan \
        wfuzz dotdotpwn xsser commix arjun paramspider whatweb \
        # --- auth / password ---
        hydra john hashcat medusa patator hash-identifier hashid ophcrack \
        crunch cewl hashcat-utils evil-winrm \
        # --- binary / RE ---
        radare2 gdb binwalk checksec ropgadget ropper foremost \
        exiftool steghide outguess zsteg upx-ucl \
        # --- forensics ---
        volatility3 sleuthkit autopsy testdisk scalpel bulk-extractor \
        # --- wireless / sniffing ---
        aircrack-ng kismet wireshark tshark tcpdump \
        # --- osint ---
        sherlock spiderfoot recon-ng maltego \
        # --- exploitation / frameworks ---
        metasploit-framework exploitdb \
        # --- RE suite & proxies (GUI, best-effort) ---
        ghidra burpsuite zaproxy \
        # --- misc / api ---
        httpie jq \
        # --- wordlists ---
        seclists wordlists \
    && rm -rf /var/lib/apt/lists/* || true

# ---------------------------------------------------------------------------
# 3) Go + tool berbasis Go (ProjectDiscovery, tomnomnom, dll.)
# ---------------------------------------------------------------------------
ARG GO_VERSION=1.23.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz \
    && for pkg in \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
        github.com/projectdiscovery/httpx/cmd/httpx \
        github.com/projectdiscovery/katana/cmd/katana \
        github.com/hahwul/dalfox/v2 \
        github.com/lc/gau/v2/cmd/gau \
        github.com/tomnomnom/waybackurls \
        github.com/tomnomnom/anew \
        github.com/tomnomnom/qsreplace \
        github.com/hakluke/hakrawler \
        github.com/jaeles-project/jaeles \
    ; do GOBIN=/root/go/bin go install "${pkg}@latest" || echo "WARN: go install ${pkg} failed"; done \
    && nuclei -update-templates || true

# ---------------------------------------------------------------------------
# 4) Cargo (Rust) tools: x8 (hidden param), pwninit (pwn setup)
# ---------------------------------------------------------------------------
RUN cargo install x8 || echo "WARN: cargo install x8 failed" \
    && cargo install pwninit || echo "WARN: cargo install pwninit failed"

# ---------------------------------------------------------------------------
# 5) Ruby gem: one_gadget
# ---------------------------------------------------------------------------
RUN gem install one_gadget --no-document || echo "WARN: gem install one_gadget failed"

# ---------------------------------------------------------------------------
# 6) Python virtualenv + requirements HexStrike (framework)
# ---------------------------------------------------------------------------
WORKDIR /opt/hexstrike-ai
RUN python3 -m venv "$VIRTUAL_ENV" \
    && pip install --upgrade pip setuptools wheel

# Copy requirements dulu supaya layer ini ke-cache saat kode berubah
COPY requirements.txt ./
RUN pip install -r requirements.txt

# ---------------------------------------------------------------------------
# 7) Tool CLI berbasis Python (di-isolasi via pipx agar tidak bentrok
#    dengan dependency framework di venv). Beberapa juga sudah dari apt;
#    pipx memastikan versi terbaru & nama biner konsisten.
# ---------------------------------------------------------------------------
RUN pipx ensurepath \
    && for app in \
        scoutsuite \
        checkov \
        prowler \
        semgrep \
        uro \
        shodan \
        censys \
        arjun \
        autorecon \
        volatility3 \
        kube-hunter \
    ; do pipx install "$app" || echo "WARN: pipx install ${app} failed"; done

# ---------------------------------------------------------------------------
# 8) Tool dari git / installer resmi:
#    libc-database, hashpump, docker-bench-security, trivy, kube-bench, terrascan
# ---------------------------------------------------------------------------
RUN mkdir -p /opt/tools/bin \
    # libc-database
    && git clone --depth 1 https://github.com/niklasb/libc-database /opt/tools/libc-database \
    && ln -sf /opt/tools/libc-database/find /opt/tools/bin/libc-database \
    # hashpump (length-extension)
    && (git clone --depth 1 https://github.com/bwall/HashPump /opt/tools/HashPump \
        && cd /opt/tools/HashPump && make && make install) || echo "WARN: hashpump build failed" \
    # docker-bench-security
    && git clone --depth 1 https://github.com/docker/docker-bench-security /opt/tools/docker-bench-security \
    && ln -sf /opt/tools/docker-bench-security/docker-bench-security.sh /opt/tools/bin/docker-bench-security

# Trivy (installer resmi) + kube-bench + terrascan
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin || echo "WARN: trivy install failed"
RUN KB_VER="$(curl -fsSL https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | jq -r .tag_name | sed 's/^v//')" \
    && curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VER}/kube-bench_${KB_VER}_linux_amd64.tar.gz" \
        | tar -C /usr/local/bin -xz kube-bench || echo "WARN: kube-bench install failed"
RUN TS_VER="$(curl -fsSL https://api.github.com/repos/tenable/terrascan/releases/latest | jq -r .tag_name | sed 's/^v//')" \
    && curl -fsSL "https://github.com/tenable/terrascan/releases/download/v${TS_VER}/terrascan_${TS_VER}_Linux_x86_64.tar.gz" \
        | tar -C /usr/local/bin -xz terrascan || echo "WARN: terrascan install failed"

# gitleaks (secret scanning untuk stage code-scan CI/CD)
RUN GL_VER="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name | sed 's/^v//')" \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz" \
        | tar -C /usr/local/bin -xz gitleaks || echo "WARN: gitleaks install failed"

# ---------------------------------------------------------------------------
# 9) Symlink alias supaya nama biner cocok dengan yang di-probe /health
#    (health check memakai nama seperti scout-suite / shodan-cli / censys-cli)
# ---------------------------------------------------------------------------
RUN set -e; \
    ln -sf "$(command -v scout   || true)" /usr/local/bin/scout-suite      2>/dev/null || true; \
    ln -sf "$(command -v shodan  || true)" /usr/local/bin/shodan-cli       2>/dev/null || true; \
    ln -sf "$(command -v censys  || true)" /usr/local/bin/censys-cli       2>/dev/null || true; \
    ln -sf "$(command -v msfconsole || true)" /usr/local/bin/metasploit    2>/dev/null || true; \
    ln -sf "$(command -v searchsploit || true)" /usr/local/bin/exploit-db  2>/dev/null || true; \
    ln -sf "$(command -v nxc || command -v netexec || true)" /usr/local/bin/nxc 2>/dev/null || true; \
    true

# ---------------------------------------------------------------------------
# 10) Copy source code aplikasi
#     Termasuk paket hexstrike_lib/ (modul single-responsibility) + entrypoint
#     tipis: hexstrike_server.py, hexstrike_mcp.py, hexstrike_ci.py,
#     hexstrike_webhook.py, hexstrike_openai_agent.py
# ---------------------------------------------------------------------------
COPY . .

# ---------------------------------------------------------------------------
# 11) Runtime
# ---------------------------------------------------------------------------
EXPOSE 8888

# Selenium browser agent butuh Chromium yang sudah kita pasang di atas
ENV CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8888/health || exit 1

# Flask API backend. MCP bridge dijalankan terpisah (hexstrike_mcp.py --server).
CMD ["python3", "hexstrike_server.py", "--port", "8888"]
