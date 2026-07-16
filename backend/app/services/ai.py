# ai.py — multi-provider AI router (BYOK)
import os
from abc import ABC, abstractmethod

class AIProvider(ABC):
    @abstractmethod
    async def analyze(self, prompt: str, image_b64: str | None = None) -> str: ...

class GeminiProvider(AIProvider):
    def __init__(self):
        self.key = os.environ["GEMINI_API_KEY"]   # set in Vercel/backend env
        self.model = "gemini-2.0-flash"             # disclose in README
    async def analyze(self, prompt, image_b64=None):
        # call https://generativelanguage.googleapis.com/... with self.key
        ...

class GrokProvider(AIProvider):
    def __init__(self):
        self.key = os.environ["GROK_API_KEY"]
        self.model = "grok-2-latest"
    async def analyze(self, prompt, image_b64=None):
        # call https://api.x.ai/v1/chat/completions
        ...

class OpenAIProvider(AIProvider):
    def __init__(self):
        self.key = os.environ["OPENAI_API_KEY"]
        self.model = "gpt-4o-mini"
    async def analyze(self, prompt, image_b64=None):
        # call https://api.openai.com/v1/chat/completions
        ...

PROVIDERS = {
    "gemini": GeminiProvider,
    "grok": GrokProvider,
    "openai": OpenAIProvider,
}

async def get_ai_insight(prompt: str, provider: str = "gemini", image_b64=None):
    return await PROVIDERS[provider]().analyze(prompt, image_b64)
