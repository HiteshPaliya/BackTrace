"""Local Ollama LLM backend integration for offline analysis."""

import json
import urllib.request
from typing import Any, Dict, Optional


class OllamaBackend:
    """Invokes local Ollama inference endpoint."""

    DEFAULT_MODEL = "deepseek-coder:6.7b"
    REQUEST_TIMEOUT = 45

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model or self.DEFAULT_MODEL

    def generate(self, prompt: str, max_tokens: int = 4096) -> Dict[str, Any]:
        """Generate completion using Ollama REST API."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = body.get("response", "")
            eval_count = body.get("eval_count", 0)
            return {"text": text, "tokens": eval_count}
