"""Gemini 3.8 Flash LLM backend integration."""

import os
from typing import Any, Dict, Optional


class GeminiBackend:
    """Invokes Google Gemini 3.8 Flash API."""

    DEFAULT_MODEL = "gemini-3.8-flash"
    REQUEST_TIMEOUT = 45

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model = model or self.DEFAULT_MODEL

    def generate(self, prompt: str, max_tokens: int = 4096) -> Dict[str, Any]:
        """Generate text completion from Gemini."""
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not provided")

        # In production this delegates to google-genai SDK or REST API
        # Using urllib.request for zero unnecessary heavy binary deps
        import json
        import urllib.request

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = (
                body.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )
            total_tokens = body.get("usageMetadata", {}).get("totalTokenCount", 0)
            return {"text": text, "tokens": total_tokens}
