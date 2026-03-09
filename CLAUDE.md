# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run locally (installs deps, starts server on :8000 with --reload)
./run.sh

# Or manually
pip install -r requirements.txt
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Docker (includes Tor proxy)
docker-compose up --build
```

There are no tests or linting configured in this project.

## Architecture

FastAPI monolith serving both a REST API (`/api/*`) and a single-page frontend (`frontend/index.html`) from the same process. SQLite with WAL mode via SQLAlchemy. No migrations — tables are auto-created from models on startup via `init_db()`.

### Request flow

1. **Targets** are created via `/api/targets` — each has a `target_type` (domain, email, keyword, brand, onion_url, ip_address) and a `value` to monitor.
2. **Scans** run either on a 15-minute scheduler tick (`services/scheduler.py` using APScheduler) or manually via `POST /api/scans/trigger/{target_id}`.
3. Both paths call `execute_scan()` in `services/scan_runner.py`, which is the central orchestrator:
   - Calls `crawler.run_scan_for_target()` to gather raw data from sources (Ahmia search, HIBP, direct Tor fetch)
   - Passes each result through `analyzer.analyze_content()` (Claude API) for threat classification
   - Persists `Finding` records with AI-generated threat levels, categories, and risk scores
4. **Dashboard** endpoints aggregate findings into stats for the frontend.

### Key design details

- `config.py` uses `pydantic-settings` — all config comes from `.env` file or environment variables. The singleton is `settings`.
- `database.get_db()` is the FastAPI dependency for DB sessions. SQLite uses `StaticPool` for thread safety.
- The crawler (`services/crawler.py`) uses `aiohttp-socks` for Tor SOCKS5 and `httpx` for HIBP. Data source selection is based on `target_type`.
- The AI analyzer returns structured JSON (threat_level, category, risk_score, summary, extracted_data) parsed from Claude's response.
- Risk score on a target is a weighted blend: `max(recent) * 0.7 + avg(recent) * 0.3` over the last 10 non-false-positive findings.
- The frontend is a standalone HTML/CSS/JS SPA — no build step. It's served via FastAPI's `StaticFiles` mount and a catch-all route.

### Environment requirements

- `ANTHROPIC_API_KEY` is required for AI analysis to function.
- Tor daemon on port 9050 is needed for .onion crawling (or use `docker-compose` which provides one).
- `HIBP_API_KEY` is optional, only needed for Have I Been Pwned email breach lookups.
- Python 3.10+ (system Python on this machine lacks `python3-venv`, use system pip directly).
