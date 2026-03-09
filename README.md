# WolfWatch — Dark Web Threat Intelligence Platform

AI-powered dark web monitoring platform that continuously scans 13+ free threat intelligence sources, analyzes findings with Claude AI, and presents actionable results through a real-time dashboard.

Built for **Wolf Industries** — fully self-hosted, Docker-ready, zero paid dependencies (except your own Anthropic API key for AI reports).

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **13+ Free Intelligence Sources** — Ahmia (Tor), AlienVault OTX, crt.sh, urlscan.io, Shodan InternetDB, abuse.ch ThreatFox & URLhaus, GreyNoise, Phishtank, HIBP, and more
- **AI-Powered Analysis** — Claude AI classifies threats, extracts IOCs (emails, IPs, credentials), and generates executive threat reports
- **Tor Proxy Pool** — 3 Tor instances behind HAProxy for parallel .onion crawling
- **SpiderFoot OSINT** — 200+ module OSINT automation platform with its own web UI
- **SearXNG Meta Search** — Self-hosted search aggregator covering 70+ engines including dark web indexes
- **Redis Caching** — Persistent cache layer for scan results
- **Auto-Scheduling** — APScheduler runs scans every 15 minutes on due targets
- **Single-Page Dashboard** — Real-time threat visualization, no build step required
- **6 Target Types** — Domain, Email, IP Address, Keyword, Brand, .onion URL

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Compose Stack                     │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                   │
│  │  Tor #1  │  │  Tor #2  │  │  Tor #3  │                   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                   │
│       └──────────┬───┴──────────┘                            │
│            ┌─────┴─────┐                                     │
│            │  HAProxy  │ :9050 (SOCKS5 load balancer)        │
│            └─────┬─────┘                                     │
│                  │                                           │
│  ┌───────────────┼────────────────────────────────────────┐  │
│  │           WolfWatch App (:8000)                        │  │
│  │                                                        │  │
│  │  FastAPI ─► Crawler ─► 13+ Sources ─► AI Analyzer     │  │
│  │     │         │              │            │            │  │
│  │     ▼         ▼              ▼            ▼            │  │
│  │  SQLite    Scheduler     Findings    Claude API        │  │
│  └───────────────┼────────────────────────────────────────┘  │
│                  │                                           │
│  ┌───────┐  ┌───┴───────┐  ┌──────────────┐                 │
│  │ Redis │  │ SpiderFoot│  │   SearXNG    │                  │
│  │ :6379 │  │   :5001   │  │    :8888     │                  │
│  └───────┘  └───────────┘  └──────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repo
git clone https://github.com/HipsDestroyerFTW/wolfwatch.git
cd wolfwatch

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Launch the full stack
docker-compose up --build
```

That's it. Open:
- **Dashboard**: http://localhost:8000
- **SpiderFoot OSINT**: http://localhost:5001
- **SearXNG Search**: http://localhost:8888
- **API Docs**: http://localhost:8000/docs

### Option 2: Local Development (No Docker)

```bash
# Requirements: Python 3.10+, Tor daemon on port 9050 (optional)

git clone https://github.com/HipsDestroyerFTW/wolfwatch.git
cd wolfwatch

# Quick start
./run.sh

# Or manually
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Configuration

All configuration is done via `.env` file or environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | — | Claude API key for AI threat analysis |
| `HIBP_API_KEY` | No | — | Have I Been Pwned key for email breach checks |
| `TOR_PROXY_HOST` | No | `127.0.0.1` | Tor SOCKS5 host (auto-set by Docker) |
| `TOR_PROXY_PORT` | No | `9050` | Tor SOCKS5 port |
| `COMPANY_NAME` | No | `Wolf Industries` | Your company name (used in AI analysis) |
| `COMPANY_DOMAINS` | No | `wolfindustries.com` | Comma-separated company domains |
| `DEFAULT_SCAN_INTERVAL_HOURS` | No | `6` | Default hours between scans |
| `MAX_CONCURRENT_CRAWLS` | No | `3` | Max parallel scan tasks |
| `GREYNOISE_API_KEY` | No | — | Free community key from greynoise.io |
| `PHISHTANK_API_KEY` | No | — | Free key from phishtank.org |
| `REDIS_URL` | No | — | Redis connection URL (auto-set by Docker) |
| `SPIDERFOOT_URL` | No | — | SpiderFoot API URL (auto-set by Docker) |
| `SEARXNG_URL` | No | — | SearXNG API URL (auto-set by Docker) |

---

## Data Sources

All sources are **free** — no paid subscriptions required.

| Source | Target Types | API Key? | What It Finds |
|---|---|---|---|
| **Ahmia (Tor)** | All | No | Dark web search results for your targets |
| **AlienVault OTX** | Domain, IP, Email | No | Threat pulses, malware, passive DNS |
| **crt.sh** | Domain | No | Certificate transparency — reveals subdomains |
| **urlscan.io** | Domain, IP, Brand, Keyword | No | Historical website scans and metadata |
| **Shodan InternetDB** | IP | No | Open ports, CVEs, hostnames |
| **abuse.ch ThreatFox** | Domain, IP | No | Malware IOC database |
| **abuse.ch URLhaus** | Domain, IP | No | Known malicious URLs |
| **GreyNoise** | IP | Optional | IP noise/threat classification |
| **Phishtank** | Onion URL | Optional | Phishing URL detection |
| **HIBP** | Email | Optional | Email breach and paste history |
| **SearXNG** | All | Self-hosted | Meta search across 70+ engines |
| **SpiderFoot** | Domain, IP, Email, Brand | Self-hosted | 200+ OSINT modules |
| **Direct Tor Fetch** | Onion URL | No | Raw .onion page content |

---

## API Reference

Base URL: `http://localhost:8000/api`

### Targets

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/targets` | List all targets |
| `POST` | `/api/targets` | Create a new target |
| `GET` | `/api/targets/{id}` | Get target details |
| `PATCH` | `/api/targets/{id}` | Update target |
| `DELETE` | `/api/targets/{id}` | Delete target |
| `POST` | `/api/targets/{id}/toggle` | Activate/deactivate |

### Scans

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/scans` | List scan history |
| `GET` | `/api/scans/{id}` | Get scan details |
| `POST` | `/api/scans/trigger/{id}` | Manually trigger a scan |

### Findings

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/findings` | List findings (filterable) |
| `GET` | `/api/findings/{id}` | Get finding details |
| `PATCH` | `/api/findings/{id}/acknowledge` | Mark acknowledged/false positive |
| `DELETE` | `/api/findings/{id}` | Delete finding |

### Dashboard

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/stats` | Aggregated dashboard KPIs |
| `GET` | `/api/dashboard/report/{id}` | AI-generated threat report |
| `GET` | `/api/health` | Health check |

### Creating a Target (Example)

```bash
curl -X POST http://localhost:8000/api/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company Domain",
    "target_type": "domain",
    "value": "example.com",
    "description": "Monitor our main domain on the dark web",
    "scan_interval_hours": 6,
    "tags": ["production", "critical"]
  }'
```

Target types: `domain`, `email`, `ip_address`, `keyword`, `brand`, `onion_url`

---

## Scaling

### Add More Tor Instances

Edit `docker-compose.yml` to add more Tor nodes:

```yaml
  tor-4:
    image: dperson/torproxy:latest
    restart: unless-stopped
    environment:
      - TZ=UTC
```

Then add the new node to `infra/haproxy.cfg`:

```
backend tor_pool
    server tor4 tor-4:9050 check inter 30s fall 3 rise 2
```

### GPU-Accelerated SpiderFoot

Uncomment the GPU section in `docker-compose.yml` if you have an NVIDIA GPU.

### Multiple App Workers

Run multiple app instances behind a reverse proxy:

```yaml
  app:
    build: .
    deploy:
      replicas: 3
```

---

## Project Structure

```
wolfwatch/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py             # Pydantic settings from .env
│   ├── database.py           # SQLAlchemy engine + session
│   ├── models.py             # ORM models (Target, Scan, Finding, AlertRule)
│   ├── schemas.py            # Pydantic request/response schemas
│   ├── routers/
│   │   ├── targets.py        # Target CRUD endpoints
│   │   ├── scans.py          # Scan trigger + history
│   │   ├── findings.py       # Findings query + acknowledge
│   │   └── dashboard.py      # Stats + AI threat reports
│   └── services/
│       ├── crawler.py         # 13+ data source orchestrator
│       ├── analyzer.py        # Claude AI threat analysis
│       ├── scan_runner.py     # Core scan execution logic
│       └── scheduler.py       # APScheduler background jobs
├── frontend/
│   └── index.html             # Single-page dashboard (no build step)
├── infra/
│   ├── haproxy.cfg            # Tor proxy pool load balancer config
│   └── searxng-settings.yml   # SearXNG meta search engine config
├── docker-compose.yml         # Full stack orchestration
├── Dockerfile                 # Python 3.12 container
├── requirements.txt           # Python dependencies
├── run.sh                     # Local dev launcher
├── .env.example               # Environment variable template
└── CLAUDE.md                  # AI coding assistant instructions
```

---

## How It Works

1. **Create a target** via the dashboard or API (domain, email, IP, etc.)
2. **Scans run automatically** every 15 minutes, or trigger manually
3. The **crawler** hits all applicable free intelligence sources in parallel
4. **Claude AI** analyzes each result — classifies threat level, extracts IOCs, scores risk
5. **Findings** appear on the dashboard with threat levels: Critical, High, Medium, Low, Informational
6. **Generate reports** — one-click AI threat intelligence reports per target
7. **Risk scores** auto-update: `max(recent) * 0.7 + avg(recent) * 0.3`

---

## License

MIT License — use it however you want.

---

Built by **Wolf Industries** with Claude AI.
