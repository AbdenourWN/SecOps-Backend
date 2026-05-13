"""
PARKED — LangChain Ollama wrapper.

Not imported by llm.py by default. To revive:
  1. Set LLM_PROVIDER=ollama in .env
  2. In llm.py, uncomment:
       from app.modules.ai.llm_local import get_ollama_model
       return get_ollama_model()
  3. Ensure Ollama is running at OLLAMA_URL with the model pulled.
"""
from langchain_core.language_models import BaseChatModel
from app.core.config import settings


def get_ollama_model() -> BaseChatModel:
    from langchain_ollama import ChatOllama
    return ChatOllama(
        model=settings.LLM_MODEL,
        base_url=settings.OLLAMA_URL,
        temperature=settings.LLM_TEMPERATURE,
        num_predict=settings.LLM_MAX_TOKENS,
    )
