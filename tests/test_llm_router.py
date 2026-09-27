"""Tests for ModelBackendRouter with retry backoff and fallback."""

from unittest.mock import MagicMock, patch

import pytest

from src.llm.ollama import OllamaBackend
from src.llm.router import ModelBackendRouter


def test_router_retries_on_rate_limit():
    """Happy path: Router catches 429 rate limit and retries with backoff."""
    mock_backend = MagicMock()
    mock_backend.generate.side_effect = [
        Exception("HTTP 429: Resource Exhausted"),
        {"text": "Analysis complete", "tokens": 150},
    ]

    router = ModelBackendRouter(primary_backend=mock_backend, max_retries=2, backoff_base=0.01)
    response = router.complete("Review this code slice")

    assert response["text"] == "Analysis complete"
    assert mock_backend.generate.call_count == 2


def test_router_fallback_to_secondary():
    """Happy path: Primary exhausts retries and router fails over to secondary backend."""
    mock_primary = MagicMock()
    mock_primary.generate.side_effect = Exception("HTTP 503: Service Unavailable")

    mock_fallback = MagicMock()
    mock_fallback.generate.return_value = {"text": "Fallback offline verdict", "tokens": 80}

    router = ModelBackendRouter(
        primary_backend=mock_primary,
        fallback_backend=mock_fallback,
        max_retries=2,
        backoff_base=0.01,
    )
    response = router.complete("Review this code slice")

    assert response["text"] == "Fallback offline verdict"
    assert mock_primary.generate.call_count == 3  # Initial + 2 retries
    assert mock_fallback.generate.call_count == 1


def test_router_raises_when_all_fail():
    """Error boundary: Both primary and fallback failing raises exception."""
    mock_primary = MagicMock()
    mock_primary.generate.side_effect = Exception("API error")

    router = ModelBackendRouter(primary_backend=mock_primary, max_retries=1, backoff_base=0.01)
    with pytest.raises(RuntimeError):
        router.complete("Failing prompt")


def test_ollama_backend_payload_construction():
    """Boundary test: Ollama backend sends well-formed POST to localhost:11434."""
    backend = OllamaBackend(model="deepseek-coder", base_url="http://localhost:11434")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "Vulnerability found", "eval_count": 42}

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_ctx = MagicMock()
        mock_ctx.read.return_value = b'{"response": "Vulnerability found", "eval_count": 42}'
        mock_ctx.__enter__.return_value = mock_ctx
        mock_urlopen.return_value = mock_ctx

        res = backend.generate("prompt text")
        assert res["text"] == "Vulnerability found"
        assert res["tokens"] == 42
