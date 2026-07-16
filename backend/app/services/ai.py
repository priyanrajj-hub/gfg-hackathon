# ai.py — AI summary generation (Gemini)
import httpx
from app.core.config import settings


async def get_ai_insight(prompt: str) -> str:
    """Call Gemini API with the given prompt and return the text response."""
    if not settings.AI_API_KEY:
        return "AI summary unavailable: no API key configured."

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.AI_MODEL}:generateContent?key={settings.AI_API_KEY}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"AI summary unavailable: {str(e)}"


async def generate_summary(scan: dict, score: int) -> str:
    """Build a prompt from scan results and get an AI-generated summary."""
    prompt = (
        "You are a security analyst. Summarize this website scan in 2-3 sentences "
        "for a non-technical stakeholder.\n\n"
        f"Security score: {score}/100\n"
        f"Scan details: {scan}"
    )
    return await get_ai_insight(prompt)
