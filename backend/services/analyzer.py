"""AI-powered threat analysis using Claude."""
import json
import re
import logging
from anthropic import AsyncAnthropic
from ..config import settings
from ..models import ThreatLevel, FindingCategory

logger = logging.getLogger(__name__)

client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

THREAT_LEVEL_SCORES = {
    ThreatLevel.CRITICAL: 9.5,
    ThreatLevel.HIGH: 7.5,
    ThreatLevel.MEDIUM: 5.0,
    ThreatLevel.LOW: 2.5,
    ThreatLevel.INFORMATIONAL: 0.5,
}

SYSTEM_PROMPT = f"""You are a dark web threat intelligence analyst for {settings.COMPANY_NAME}.
Your job is to analyze raw content found on dark web sources and assess its threat level to the organization.

When analyzing content, always return a valid JSON object with this exact structure:
{{
  "threat_level": "critical|high|medium|low|informational",
  "category": "credential_leak|data_breach|brand_mention|infrastructure_exposure|threat_actor|fraud|other",
  "title": "Brief descriptive title (max 100 chars)",
  "summary": "2-3 sentence summary of the threat and its potential impact",
  "analysis": "Detailed analysis: what was found, why it's relevant, recommended actions",
  "extracted_data": {{
    "emails": [],
    "domains": [],
    "passwords": [],
    "ips": [],
    "usernames": [],
    "credit_cards": [],
    "other": []
  }},
  "risk_score": 0.0
}}

Threat level guidance:
- CRITICAL: Active credential dumps, imminent attack indicators, executive PII, financial data
- HIGH: Historical breaches, brand impersonation, employee data exposure
- MEDIUM: Brand mentions in threat forums, partial data exposure
- LOW: General dark web chatter, non-specific mentions
- INFORMATIONAL: Neutral mentions, no immediate threat

risk_score should be 0.0-10.0 matching the threat level approximately.
"""


async def analyze_content(
    target_value: str,
    target_type: str,
    source_name: str,
    raw_content: str,
    source_url: str = "",
) -> dict:
    """Run Claude AI analysis on scraped dark web content."""
    if not settings.ANTHROPIC_API_KEY:
        return _mock_analysis(target_value, source_name)

    # Truncate very long content to keep token usage reasonable
    content_preview = raw_content[:8000] if len(raw_content) > 8000 else raw_content

    user_message = f"""Analyze the following content found while monitoring for "{target_value}" (type: {target_type}).

Source: {source_name}
URL: {source_url or "unknown"}

---CONTENT START---
{content_preview}
---CONTENT END---

Return your analysis as a JSON object following the exact structure specified."""

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        text = response.content[0].text.strip()

        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
        else:
            result = json.loads(text)

        # Normalize enum values
        result["threat_level"] = _normalize_threat_level(result.get("threat_level", "informational"))
        result["category"] = _normalize_category(result.get("category", "other"))
        result.setdefault("risk_score", THREAT_LEVEL_SCORES.get(result["threat_level"], 0.5))
        result.setdefault("extracted_data", {})
        return result

    except Exception as exc:
        logger.error("AI analysis failed: %s", exc)
        return _fallback_analysis(target_value, source_name, str(exc))


async def generate_threat_report(findings: list[dict], target: dict) -> str:
    """Generate a markdown threat intelligence report for a target."""
    if not settings.ANTHROPIC_API_KEY or not findings:
        return "AI report generation requires a valid ANTHROPIC_API_KEY."

    findings_text = json.dumps(findings[:20], indent=2, default=str)

    response = await client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": f"""Generate a concise threat intelligence report for {settings.COMPANY_NAME}.

Target: {target.get('name')} ({target.get('value')})
Type: {target.get('target_type')}

Recent Findings (last 20):
{findings_text}

Write a professional threat intelligence report in markdown format covering:
1. Executive Summary
2. Key Threats Identified
3. Data Exposure Assessment
4. Recommended Immediate Actions
5. Long-term Mitigation Steps

Keep it actionable and concise."""
        }],
    )
    return response.content[0].text


def _normalize_threat_level(value: str) -> str:
    valid = {t.value for t in ThreatLevel}
    value = value.lower().strip()
    return value if value in valid else "informational"


def _normalize_category(value: str) -> str:
    valid = {c.value for c in FindingCategory}
    value = value.lower().strip().replace(" ", "_").replace("-", "_")
    return value if value in valid else "other"


def _mock_analysis(target_value: str, source_name: str) -> dict:
    """Return a placeholder when no API key is configured."""
    return {
        "threat_level": "informational",
        "category": "other",
        "title": f"Match found for {target_value}",
        "summary": f"Content matching '{target_value}' was found on {source_name}. Configure ANTHROPIC_API_KEY for AI analysis.",
        "analysis": "AI analysis disabled — set ANTHROPIC_API_KEY in .env to enable Claude-powered threat assessment.",
        "extracted_data": {"emails": [], "domains": [], "passwords": [], "ips": [], "usernames": [], "other": []},
        "risk_score": 1.0,
    }


def _fallback_analysis(target_value: str, source_name: str, error: str) -> dict:
    return {
        "threat_level": "medium",
        "category": "other",
        "title": f"Content found for {target_value} (analysis error)",
        "summary": f"Raw content matching '{target_value}' was detected on {source_name}, but AI analysis failed.",
        "analysis": f"Analysis error: {error}. Manual review recommended.",
        "extracted_data": {"emails": [], "domains": [], "passwords": [], "ips": [], "usernames": [], "other": []},
        "risk_score": 4.0,
    }
