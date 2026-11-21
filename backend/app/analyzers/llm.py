from typing import Protocol

from app.core.config import settings


class LLM(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class AnthropicLLM:
    def __init__(self, api_key: str, model: str):
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key, timeout=60.0, max_retries=2)
        self._model = model

    def complete(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model, max_tokens=2000, system=system,
            messages=[{"role": "user", "content": user}],  # no tools are ever passed
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def get_llm() -> LLM | None:
    """Only the analyst service calls this. No key means the rules-based fallback."""
    if not settings.anthropic_api_key:
        return None
    return AnthropicLLM(settings.anthropic_api_key, settings.anthropic_model)
