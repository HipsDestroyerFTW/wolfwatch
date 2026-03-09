"""Dark web & threat intel crawler.

Working data sources (all free, no paid APIs):
  - Have I Been Pwned       — email breach/paste lookup (requires free HIBP_API_KEY)
  - AlienVault OTX          — free threat intel: domain/IP/email reputation
  - crt.sh                  — certificate transparency logs (domain/brand)
  - urlscan.io              — passive website scan history (domain/IP)
  - Tor .onion fetch        — direct .onion content via SOCKS5 proxy
  - Ahmia .onion            — dark web search via Tor proxy
  - Shodan InternetDB       — IP enrichment (completely free, no key)
  - abuse.ch ThreatFox      — malware IOC database (free)
  - abuse.ch URLhaus        — malicious URL database (free)
  - GreyNoise Community     — IP noise/threat classification (free)
  - Phishtank               — phishing URL database (free)
  - SearXNG                 — meta search aggregation (self-hosted)
  - SpiderFoot              — OSINT automation (self-hosted)
"""
import asyncio
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import aiohttp
import httpx
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup

from ..config import settings
from ..models import TargetType

logger = logging.getLogger(__name__)

# ─── Free API endpoints ─────────────────────────────────────────────────────
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_PASTE_URL  = "https://haveibeenpwned.com/api/v3/pasteaccount/{account}"
OTX_BASE        = "https://otx.alienvault.com/api/v1/indicators"
CRTSH_URL       = "https://crt.sh/?q={query}&output=json"
URLSCAN_URL     = "https://urlscan.io/api/v1/search/?q={query}&size=20"
AHMIA_ONION     = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"

# New free sources
SHODAN_INTERNETDB = "https://internetdb.shodan.io/{ip}"
THREATFOX_URL     = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL       = "https://urlhaus-api.abuse.ch/v1/"
GREYNOISE_URL     = "https://api.greynoise.io/v3/community/{ip}"
PHISHTANK_URL     = "https://checkurl.phishtank.com/checkurl/"


@dataclass
class CrawlResult:
    source_name: str
    source_url: str
    raw_content: str
    matched: bool = True
    error: Optional[str] = None


def _session(timeout: int = 15) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "application/json, text/html, */*",
        },
        timeout=aiohttp.ClientTimeout(total=timeout),
    )


def _tor_session(timeout: int = 45) -> aiohttp.ClientSession:
    connector = ProxyConnector.from_url(settings.tor_socks_url)
    return aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
        timeout=aiohttp.ClientTimeout(total=timeout),
    )


# ─── Have I Been Pwned ───────────────────────────────────────────────────────

async def check_hibp_email(email: str) -> list[CrawlResult]:
    if not settings.HIBP_API_KEY:
        logger.info("HIBP_API_KEY not configured — skipping HIBP for %s", email)
        return []

    results = []
    headers = {
        "hibp-api-key": settings.HIBP_API_KEY,
        "User-Agent": f"{settings.COMPANY_NAME} DarkWeb Monitor",
    }
    async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as s:
        for kind, url_tmpl in [("Breaches", HIBP_BREACH_URL), ("Pastes", HIBP_PASTE_URL)]:
            try:
                async with s.get(url_tmpl.format(account=email)) as r:
                    if r.status == 200:
                        data = await r.json()
                        names = [b.get("Name", b.get("Source", "unknown")) for b in data]
                        results.append(CrawlResult(
                            source_name=f"Have I Been Pwned ({kind})",
                            source_url=f"https://haveibeenpwned.com/account/{email}",
                            raw_content=(
                                f"Email address {email} was found in {len(data)} {kind.lower()}.\n"
                                f"Sources: {', '.join(names)}\n"
                                f"Full data: {json.dumps(data[:5], indent=2)}"
                            ),
                        ))
                    elif r.status == 404:
                        logger.debug("HIBP %s: %s not found", kind, email)
            except Exception as exc:
                logger.warning("HIBP %s check error for %s: %s", kind, email, exc)
    return results


# ─── AlienVault OTX ──────────────────────────────────────────────────────────

async def check_otx(value: str, target_type: str) -> list[CrawlResult]:
    """Query AlienVault OTX for threat intelligence on a domain, IP, or email."""
    type_map = {
        TargetType.DOMAIN:     ("domain", ["general", "malware", "url_list", "passive_dns"]),
        TargetType.IP_ADDRESS: ("IPv4",   ["general", "malware", "passive_dns"]),
        TargetType.EMAIL:      ("email",  ["general"]),
    }
    if target_type not in type_map:
        return []

    indicator_type, sections = type_map[target_type]
    results = []

    async with _session(timeout=15) as s:
        for section in sections:
            url = f"{OTX_BASE}/{indicator_type}/{value}/{section}"
            try:
                async with s.get(url) as r:
                    if r.status != 200:
                        continue
                    data = await r.json()
                    if not data:
                        continue

                    content = _otx_to_text(section, value, data)
                    if content:
                        results.append(CrawlResult(
                            source_name=f"AlienVault OTX ({section})",
                            source_url=f"https://otx.alienvault.com/indicator/{indicator_type}/{value}",
                            raw_content=content,
                        ))
            except Exception as exc:
                logger.warning("OTX %s/%s error: %s", value, section, exc)

    return results


def _otx_to_text(section: str, value: str, data: dict) -> str:
    """Convert OTX API response to plain text for AI analysis."""
    lines = [f"AlienVault OTX intelligence for: {value}", f"Section: {section}", ""]

    if section == "general":
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        reputation  = data.get("reputation", 0)
        country     = data.get("country_name", "unknown")
        asn         = data.get("asn", "unknown")
        lines += [
            f"Threat pulse count: {pulse_count}",
            f"Reputation score: {reputation}",
            f"Country: {country}",
            f"ASN: {asn}",
        ]
        pulses = data.get("pulse_info", {}).get("pulses", [])[:5]
        if pulses:
            lines.append("\nThreat pulses:")
            for p in pulses:
                lines.append(f"  - [{p.get('TLP','?')}] {p.get('name','?')} (tags: {', '.join(p.get('tags',[])[:5])})")

        if pulse_count == 0 and reputation == 0:
            return ""  # Nothing interesting

    elif section == "malware":
        count = data.get("count", 0)
        if count == 0:
            return ""
        lines.append(f"Malware samples associated: {count}")
        for item in data.get("data", [])[:5]:
            lines.append(f"  - {item.get('hash','?')} ({item.get('detections',{}).get('count',0)} detections)")

    elif section == "url_list":
        urls = data.get("url_list", [])
        if not urls:
            return ""
        lines.append(f"Associated URLs ({len(urls)} found):")
        for u in urls[:10]:
            lines.append(f"  - {u.get('url','?')} [result: {u.get('result',{}).get('urlworker',{}).get('http_code','?')}]")

    elif section == "passive_dns":
        records = data.get("passive_dns", [])
        if not records:
            return ""
        lines.append(f"Passive DNS records ({len(records)} found):")
        for r in records[:10]:
            lines.append(f"  - {r.get('hostname','?')} -> {r.get('address','?')} (first: {r.get('first','?')})")

    return "\n".join(lines)


# ─── Certificate Transparency (crt.sh) ───────────────────────────────────────

async def check_crtsh(domain: str) -> list[CrawlResult]:
    """Search certificate transparency logs for a domain — reveals subdomains and history."""
    url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            r = await client.get(url, headers={"Accept": "application/json"})
            if r.status_code != 200:
                return []
            data = r.json()

        if not data:
            return []

        seen = set()
        names = []
        for entry in data:
            cn = entry.get("common_name", "") or entry.get("name_value", "")
            for name in cn.split("\n"):
                name = name.strip().lower()
                if name and name not in seen:
                    seen.add(name)
                    names.append({
                        "name": name,
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    })

        names = names[:50]
        content = (
            f"Certificate transparency log results for {domain}\n"
            f"Total unique names found: {len(seen)}\n\n"
            f"Recent certificate entries ({len(names)} shown):\n"
            + "\n".join(f"  - {n['name']} (issued: {n['not_before'][:10]}, issuer: {n['issuer'][:60]})" for n in names[:20])
        )

        return [CrawlResult(
            source_name="Certificate Transparency (crt.sh)",
            source_url=f"https://crt.sh/?q=%.{domain}",
            raw_content=content,
        )]
    except Exception as exc:
        logger.warning("crt.sh check failed for %s: %s", domain, exc)
        return []


# ─── urlscan.io ──────────────────────────────────────────────────────────────

async def check_urlscan(value: str, target_type: str) -> list[CrawlResult]:
    """Search urlscan.io for historical scans of a domain or IP."""
    if target_type == TargetType.DOMAIN:
        query = f"domain:{value}"
    elif target_type == TargetType.IP_ADDRESS:
        query = f"ip:{value}"
    elif target_type in (TargetType.BRAND, TargetType.KEYWORD):
        query = f"page.title:{value} OR page.domain:{value}"
    else:
        return []

    url = URLSCAN_URL.format(query=urllib.parse.quote(query))
    try:
        async with _session() as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        results_data = data.get("results", [])
        if not results_data:
            return []

        lines = [
            f"urlscan.io results for: {value}",
            f"Total hits: {data.get('total', len(results_data))}",
            "",
        ]
        for item in results_data[:15]:
            pg   = item.get("page", {})
            task = item.get("task", {})
            lines.append(
                f"  [{task.get('time','?')[:10]}] {pg.get('url','?')}\n"
                f"    Title: {pg.get('title','N/A')}\n"
                f"    IP: {pg.get('ip','?')} | Country: {pg.get('country','?')}\n"
                f"    Report: https://urlscan.io/result/{item.get('_id','')}"
            )

        return [CrawlResult(
            source_name="urlscan.io",
            source_url=f"https://urlscan.io/search/#{urllib.parse.quote(query)}",
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.warning("urlscan.io check failed for %s: %s", value, exc)
        return []


# ─── Shodan InternetDB (completely free, no API key) ─────────────────────────

async def check_shodan_internetdb(ip: str) -> list[CrawlResult]:
    """Query Shodan InternetDB for open ports, vulns, and hostnames on an IP."""
    url = SHODAN_INTERNETDB.format(ip=ip)
    try:
        async with _session() as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])
        tags = data.get("tags", [])

        if not ports and not vulns:
            return []

        lines = [
            f"Shodan InternetDB results for: {ip}",
            f"Open ports: {', '.join(str(p) for p in ports)}" if ports else "Open ports: none",
            f"Vulnerabilities ({len(vulns)}): {', '.join(vulns[:20])}" if vulns else "Vulnerabilities: none",
            f"Hostnames: {', '.join(hostnames[:10])}" if hostnames else "Hostnames: none",
            f"CPEs: {', '.join(cpes[:10])}" if cpes else "",
            f"Tags: {', '.join(tags)}" if tags else "",
        ]

        return [CrawlResult(
            source_name="Shodan InternetDB",
            source_url=f"https://internetdb.shodan.io/{ip}",
            raw_content="\n".join(l for l in lines if l),
        )]
    except Exception as exc:
        logger.warning("Shodan InternetDB check failed for %s: %s", ip, exc)
        return []


# ─── abuse.ch ThreatFox (free malware IOC database) ──────────────────────────

async def check_threatfox(value: str, target_type: str) -> list[CrawlResult]:
    """Search ThreatFox for IOCs matching a domain, IP, or keyword."""
    if target_type == TargetType.DOMAIN:
        payload = {"query": "search_ioc", "search_term": value}
    elif target_type == TargetType.IP_ADDRESS:
        payload = {"query": "search_ioc", "search_term": value}
    else:
        return []

    try:
        async with _session() as s:
            async with s.post(THREATFOX_URL, json=payload) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        status = data.get("query_status", "")
        if status != "ok":
            return []

        iocs = data.get("data", [])
        if not iocs:
            return []

        lines = [
            f"ThreatFox IOC results for: {value}",
            f"Total IOCs found: {len(iocs)}",
            "",
        ]
        for ioc in iocs[:15]:
            lines.append(
                f"  - IOC: {ioc.get('ioc', '?')}\n"
                f"    Type: {ioc.get('ioc_type', '?')} | Threat: {ioc.get('threat_type', '?')}\n"
                f"    Malware: {ioc.get('malware_printable', '?')}\n"
                f"    Confidence: {ioc.get('confidence_level', '?')}%\n"
                f"    First seen: {ioc.get('first_seen_utc', '?')}\n"
                f"    Tags: {', '.join(ioc.get('tags', []) or [])}"
            )

        return [CrawlResult(
            source_name="abuse.ch ThreatFox",
            source_url="https://threatfox.abuse.ch/browse/",
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.warning("ThreatFox check failed for %s: %s", value, exc)
        return []


# ─── abuse.ch URLhaus (free malicious URL database) ──────────────────────────

async def check_urlhaus(value: str, target_type: str) -> list[CrawlResult]:
    """Search URLhaus for malicious URLs associated with a domain or IP."""
    if target_type == TargetType.DOMAIN:
        endpoint = f"{URLHAUS_URL}host/"
        payload = {"host": value}
    elif target_type == TargetType.IP_ADDRESS:
        endpoint = f"{URLHAUS_URL}host/"
        payload = {"host": value}
    else:
        return []

    try:
        async with _session() as s:
            async with s.post(endpoint, data=payload) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        status = data.get("query_status", "")
        urls = data.get("urls", [])
        if status in ("no_results", "") or not urls:
            return []

        lines = [
            f"URLhaus malicious URL results for: {value}",
            f"Total malicious URLs: {data.get('urls_online', 0)} online, {len(urls)} total",
            f"Host status: {data.get('host', {}) if isinstance(data.get('host'), str) else value}",
            "",
        ]
        for entry in urls[:15]:
            lines.append(
                f"  - URL: {entry.get('url', '?')}\n"
                f"    Status: {entry.get('url_status', '?')} | Threat: {entry.get('threat', '?')}\n"
                f"    Date added: {entry.get('date_added', '?')}\n"
                f"    Tags: {', '.join(entry.get('tags', []) or [])}"
            )

        return [CrawlResult(
            source_name="abuse.ch URLhaus",
            source_url=f"https://urlhaus.abuse.ch/host/{value}/",
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.warning("URLhaus check failed for %s: %s", value, exc)
        return []


# ─── GreyNoise Community (free IP threat classification) ─────────────────────

async def check_greynoise(ip: str) -> list[CrawlResult]:
    """Query GreyNoise community API for IP threat/noise classification."""
    url = GREYNOISE_URL.format(ip=ip)
    headers = {}
    if settings.GREYNOISE_API_KEY:
        headers["key"] = settings.GREYNOISE_API_KEY

    try:
        async with _session() as s:
            async with s.get(url, headers=headers) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        name = data.get("name", "unknown")
        last_seen = data.get("last_seen", "unknown")

        if not noise and not riot and classification == "unknown":
            return []

        lines = [
            f"GreyNoise Community results for: {ip}",
            f"Classification: {classification}",
            f"Noise (internet scanner): {noise}",
            f"RIOT (known benign): {riot}",
            f"Name: {name}",
            f"Last seen: {last_seen}",
            f"Link: {data.get('link', '')}",
            f"Message: {data.get('message', '')}",
        ]

        return [CrawlResult(
            source_name="GreyNoise Community",
            source_url=f"https://viz.greynoise.io/ip/{ip}",
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.warning("GreyNoise check failed for %s: %s", ip, exc)
        return []


# ─── Phishtank (free phishing URL database) ──────────────────────────────────

async def check_phishtank(url_to_check: str) -> list[CrawlResult]:
    """Check if a URL is in Phishtank's phishing database."""
    payload = {
        "url": url_to_check,
        "format": "json",
    }
    if settings.PHISHTANK_API_KEY:
        payload["app_key"] = settings.PHISHTANK_API_KEY

    try:
        async with _session() as s:
            async with s.post(PHISHTANK_URL, data=payload) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        results = data.get("results", {})
        if not results.get("in_database", False):
            return []

        lines = [
            f"Phishtank results for: {url_to_check}",
            f"In database: YES",
            f"Valid phish: {results.get('valid', 'unknown')}",
            f"Verified: {results.get('verified', 'unknown')}",
            f"Verified at: {results.get('verified_at', 'unknown')}",
            f"Phish detail: {results.get('phish_detail_url', '')}",
        ]

        return [CrawlResult(
            source_name="Phishtank",
            source_url=results.get("phish_detail_url", PHISHTANK_URL),
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.warning("Phishtank check failed for %s: %s", url_to_check, exc)
        return []


# ─── SearXNG Meta Search (self-hosted) ───────────────────────────────────────

async def search_searxng(query: str, categories: str = "general") -> list[CrawlResult]:
    """Search via self-hosted SearXNG instance for broader coverage."""
    if not settings.SEARXNG_URL:
        return []

    url = f"{settings.SEARXNG_URL}/search"
    params = {
        "q": query,
        "format": "json",
        "categories": categories,
    }

    try:
        async with _session(timeout=20) as s:
            async with s.get(url, params=params) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        search_results = data.get("results", [])
        if not search_results:
            return []

        results = []
        for item in search_results[:10]:
            title = item.get("title", "")
            link = item.get("url", "")
            snippet = item.get("content", "")
            engine = item.get("engine", "unknown")

            if title or snippet:
                results.append(CrawlResult(
                    source_name=f"SearXNG ({engine})",
                    source_url=link,
                    raw_content=f"Title: {title}\nURL: {link}\nSnippet: {snippet}\nEngine: {engine}",
                ))
        return results
    except Exception as exc:
        logger.info("SearXNG search unavailable for %s: %s", query, exc)
        return []


async def search_searxng_onions(query: str) -> list[CrawlResult]:
    """Search via SearXNG specifically for .onion results."""
    if not settings.SEARXNG_URL:
        return []
    return await search_searxng(query, categories="onions")


# ─── SpiderFoot OSINT (self-hosted) ──────────────────────────────────────────

async def search_spiderfoot(value: str, target_type: str) -> list[CrawlResult]:
    """Query SpiderFoot REST API for OSINT data on a target."""
    if not settings.SPIDERFOOT_URL:
        return []

    # Map our target types to SpiderFoot scan types
    sf_type_map = {
        TargetType.DOMAIN: "INTERNET_NAME",
        TargetType.IP_ADDRESS: "IP_ADDRESS",
        TargetType.EMAIL: "EMAILADDR",
        TargetType.BRAND: "HUMAN_NAME",
    }
    sf_type = sf_type_map.get(target_type)
    if not sf_type:
        return []

    base = settings.SPIDERFOOT_URL.rstrip("/")

    try:
        # Search existing scan results for this target
        async with _session(timeout=30) as s:
            async with s.get(f"{base}/api/search", params={"value": value}) as r:
                if r.status != 200:
                    return []
                data = await r.json()

        if not data:
            return []

        lines = [
            f"SpiderFoot OSINT results for: {value}",
            f"Total data elements: {len(data)}",
            "",
        ]
        for item in data[:20]:
            lines.append(
                f"  - [{item.get('type', '?')}] {item.get('data', '?')}\n"
                f"    Module: {item.get('module', '?')} | Source: {item.get('source', '?')}"
            )

        return [CrawlResult(
            source_name="SpiderFoot OSINT",
            source_url=f"{base}/",
            raw_content="\n".join(lines),
        )]
    except Exception as exc:
        logger.info("SpiderFoot query unavailable for %s: %s", value, exc)
        return []


# ─── Tor / Ahmia .onion ───────────────────────────────────────────────────────

async def search_ahmia_tor(query: str) -> list[CrawlResult]:
    """Search Ahmia's official .onion site via Tor proxy."""
    url = AHMIA_ONION.format(query=urllib.parse.quote(query))
    try:
        async with _tor_session() as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return []
                html = await r.text(errors="replace")

        soup = BeautifulSoup(html, "lxml")
        items = soup.select("li.result")
        if not items:
            items = soup.select(".result")

        results = []
        for item in items[:15]:
            title_el = item.select_one("h4") or item.select_one("a")
            desc_el  = item.select_one("p") or item.select_one(".description")
            onion_el = item.select_one("cite") or item.select_one(".onion-url")
            title    = title_el.get_text(strip=True) if title_el else "Unknown"
            desc     = desc_el.get_text(strip=True) if desc_el else ""
            onion    = onion_el.get_text(strip=True) if onion_el else ""

            if title or desc:
                results.append(CrawlResult(
                    source_name="Ahmia Dark Web Search (Tor)",
                    source_url=onion or url,
                    raw_content=f"Title: {title}\nURL: {onion}\nDescription: {desc}",
                ))
        return results
    except Exception as exc:
        logger.info("Ahmia Tor search unavailable for %s: %s", query, exc)
        return []


async def fetch_onion_url(url: str) -> CrawlResult:
    """Fetch a .onion page directly via Tor SOCKS5."""
    try:
        async with _tor_session() as s:
            async with s.get(url) as r:
                html = await r.text(errors="replace")
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "nav", "footer"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        return CrawlResult(
            source_name=f"Onion Site: {url[:60]}",
            source_url=url,
            raw_content=text[:10000],
        )
    except Exception as exc:
        logger.warning("Onion fetch failed for %s: %s", url, exc)
        return CrawlResult(
            source_name=f"Onion Site: {url[:60]}",
            source_url=url,
            raw_content="",
            matched=False,
            error=str(exc),
        )


# ─── Orchestrator ─────────────────────────────────────────────────────────────

async def run_scan_for_target(target_value: str, target_type: str) -> list[CrawlResult]:
    """Dispatch all applicable sources for the given target type."""
    tasks: list = []

    if target_type == TargetType.EMAIL:
        tasks += [
            check_hibp_email(target_value),
            check_otx(target_value, target_type),
            search_ahmia_tor(target_value),
            search_searxng(f'"{target_value}" leak OR breach OR paste'),
            search_spiderfoot(target_value, target_type),
        ]

    elif target_type == TargetType.DOMAIN:
        tasks += [
            check_otx(target_value, target_type),
            check_crtsh(target_value),
            check_urlscan(target_value, target_type),
            check_threatfox(target_value, target_type),
            check_urlhaus(target_value, target_type),
            search_ahmia_tor(target_value),
            search_searxng(f'"{target_value}" dark web OR hack OR leak'),
            search_searxng_onions(target_value),
            search_spiderfoot(target_value, target_type),
        ]

    elif target_type == TargetType.IP_ADDRESS:
        tasks += [
            check_otx(target_value, target_type),
            check_urlscan(target_value, target_type),
            check_shodan_internetdb(target_value),
            check_threatfox(target_value, target_type),
            check_urlhaus(target_value, target_type),
            check_greynoise(target_value),
            search_ahmia_tor(target_value),
            search_spiderfoot(target_value, target_type),
        ]

    elif target_type in (TargetType.KEYWORD, TargetType.BRAND):
        tasks += [
            check_urlscan(target_value, target_type),
            search_ahmia_tor(target_value),
            search_searxng(f'"{target_value}" dark web OR leak OR breach'),
            search_searxng_onions(target_value),
            search_spiderfoot(target_value, target_type),
        ]

    elif target_type == TargetType.ONION_URL:
        tasks += [
            fetch_onion_url(target_value),
            search_ahmia_tor(target_value),
            check_phishtank(target_value),
        ]

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    all_results: list[CrawlResult] = []
    for item in gathered:
        if isinstance(item, Exception):
            logger.error("Scan task raised: %s", item)
        elif isinstance(item, list):
            all_results.extend(item)
        elif isinstance(item, CrawlResult):
            all_results.append(item)

    # Only keep results with actual content
    return [r for r in all_results if r.raw_content and not r.error]
