"""
LLM factory — returns a LangChain BaseChatModel based on LLM_PROVIDER config.

Default: openrouter (one API key → ~300 models, switch by changing LLM_MODEL only).
Alternates: anthropic, openai.
Parked: ollama (see llm_local.py — wire in the `ollama` branch below to revive).

Model name examples:
  openrouter:  "anthropic/claude-sonnet-4-6", "openai/gpt-5", "meta-llama/llama-3.3-70b-instruct"
  anthropic:   "claude-sonnet-4-6", "claude-opus-4-7"
  openai:      "gpt-5", "gpt-4o"
  ollama:      "llama3:latest", "mistral"
"""
from functools import lru_cache
from typing import Optional
from langchain_core.language_models import BaseChatModel
from app.core.config import settings


# Cache size is small but > 1 because callers may request different
# max_tokens budgets (server-overview wants a larger budget than triage).
# Each distinct budget gets its own cached client instance.
@lru_cache(maxsize=8)
def get_chat_model(max_tokens_override: Optional[int] = None) -> BaseChatModel:
    """
    Return a configured LangChain chat model.

    `max_tokens_override` lets a specific call site (e.g. the server-overview
    agent) request a higher generation budget than the global `LLM_MAX_TOKENS`
    default without affecting other callers (triage stays cheap).
    Pass `None` (the default) to use `settings.LLM_MAX_TOKENS`.
    """
    provider = settings.LLM_PROVIDER
    model = settings.LLM_MODEL
    temperature = settings.LLM_TEMPERATURE
    max_tokens = max_tokens_override if max_tokens_override is not None else settings.LLM_MAX_TOKENS

    if provider == "openrouter":
        if not settings.OPENROUTER_API_KEY:
            raise RuntimeError("OPENROUTER_API_KEY is required when LLM_PROVIDER=openrouter")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            openai_api_key=settings.OPENROUTER_API_KEY.get_secret_value(),
            openai_api_base=settings.OPENROUTER_BASE_URL,
            default_headers={
                "HTTP-Referer": settings.OPENROUTER_SITE_URL,
                "X-Title": settings.OPENROUTER_SITE_NAME,
            },
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "anthropic":
        if not settings.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            api_key=settings.ANTHROPIC_API_KEY.get_secret_value(),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "openai":
        if not settings.OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY is required when LLM_PROVIDER=openai")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=settings.OPENAI_API_KEY.get_secret_value(),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "ollama":
        # To revive: uncomment the import below and ensure llm_local.py is wired.
        # from app.modules.ai.llm_local import get_ollama_model
        # return get_ollama_model()
        raise RuntimeError(
            "LLM_PROVIDER=ollama is parked. "
            "To revive: uncomment the ollama branch in llm.py and ensure Ollama is running. "
            "See app/modules/ai/legacy/ollama_service.py for the original direct implementation."
        )

    raise RuntimeError(f"Unknown LLM_PROVIDER: {provider!r}. Valid: openrouter, anthropic, openai, ollama")
