"""ModelBackendRouter handling rate-limiting retries, backoff, and local fallback."""

import time
from typing import Any, Dict, Optional


class ModelBackendRouter:
    """Routes LLM inference with exponential backoff on 429/503 and automatic failover."""

    def __init__(
        self,
        primary_backend: Any,
        fallback_backend: Optional[Any] = None,
        max_retries: int = 3,
        backoff_base: float = 1.0,
    ) -> None:
        self.primary_backend = primary_backend
        self.fallback_backend = fallback_backend
        self.max_retries = max_retries
        self.backoff_base = backoff_base

    def complete(self, prompt: str, max_tokens: int = 4096) -> Dict[str, Any]:
        """Execute completion with retry backoff and fallback on exhaustion."""
        last_exception: Optional[Exception] = None

        # 1. Attempt with primary backend
        for attempt in range(self.max_retries + 1):
            try:
                return self.primary_backend.generate(prompt, max_tokens=max_tokens)
            except Exception as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    sleep_time = self.backoff_base * (2**attempt)
                    time.sleep(sleep_time)

        # 2. Attempt with fallback backend if available
        if self.fallback_backend:
            try:
                return self.fallback_backend.generate(prompt, max_tokens=max_tokens)
            except Exception as fb_exc:
                err_msg = (
                    f"Primary and fallback backends failed. "
                    f"Primary: {last_exception}; Fallback: {fb_exc}"
                )
                raise RuntimeError(err_msg) from fb_exc

        raise RuntimeError(
            f"Primary backend failed after {self.max_retries} retries: {last_exception}"
        ) from last_exception
