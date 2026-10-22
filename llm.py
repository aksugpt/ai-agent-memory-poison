"""Builds the chat model (local Ollama or cloud Groq) that the agent talks to."""
import os

import config


def get_llm(temperature: float = 0.0):
    """Return a LangChain chat model for the provider chosen in config.LLM_PROVIDER."""
    # Cloud model on Groq: needs an API key in the environment (.env).
    if config.LLM_PROVIDER == "groq":
        from langchain_groq import ChatGroq  # imported here so Groq is only needed when used

        if not os.getenv("GROQ_API_KEY"):
            raise RuntimeError("GROQ_API_KEY is not set (put it in .env)")
        return ChatGroq(model=config.GROQ_MODEL, temperature=temperature)

    # Local model served by Ollama on this machine.
    if config.LLM_PROVIDER == "ollama":
        from langchain_ollama import ChatOllama  # imported here so Ollama is only needed when used

        return ChatOllama(
            model=config.OLLAMA_MODEL,
            base_url=config.OLLAMA_BASE_URL,
            temperature=temperature,
        )

    # Anything else is a configuration mistake.
    raise ValueError(f"Unknown LLM_PROVIDER: {config.LLM_PROVIDER}")
