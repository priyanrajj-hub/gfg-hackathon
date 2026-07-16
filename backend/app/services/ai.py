"""
BYOK AI integration. Provider + model version are disclosed in README (per rulebook).
This module ONLY generates natural-language summaries/remediation text from
REAL scan data produced by services/scanner.py. It never fabricates findings,
never executes code, and is not used to disguise rule-based logic as AI.
"""
import httpx
from app.core.config import settings

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"


async def generate_summary(scan_result: dict, score: int) -> dict:
    if not settings.AI_API_KEY:
        return {
            "executive_summary": "AI_API_KEY not configured — set AI_API_KEY env var to enable AI summaries.",
            "technical_summary": None,
            "remediation": None,
        }

    prompt = f"""You are a security analyst. Given this vulnerability scan result and a
deterministic security score of {score}/100, produce:
1. A 2-sentence executive summary (non-technical, for leadership).
2. A technical summary of the specific issues found.
3. Prioritized remediation steps.
Scan data: {scan_result}
Respond ONLY in JSON with keys: executive_summary, technical_summary, remediation.
"""

    if settings.AI_PROVIDER == "gemini":
        url = GEMINI_URL.format(model=settings.AI_MODEL, key=settings.AI_API_KEY)
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload)
            data = resp.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            return {"executive_summary": "AI call failed or returned unexpected format.",
                     "technical_summary": str(data), "remediation": None}
        return {"raw_ai_response": text}

    return {"executive_summary": f"Unsupported AI_PROVIDER '{settings.AI_PROVIDER}'."}
