"""LLM client abstraction for multiple providers."""

import json
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass

from core.config import get_settings
from core.logger import get_logger


@dataclass
class Message:
    """Chat message."""
    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    model: str
    usage: dict


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    async def chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat completion request."""
        pass

    @abstractmethod
    async def stream_chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream chat completion."""
        pass


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude client."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or get_settings().anthropic_api_key
        self.model = model
        self.logger = get_logger("ai.anthropic")

        if not self.api_key:
            raise ValueError("Anthropic API key not configured. Set SECSUITE_ANTHROPIC_API_KEY")

    async def chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat to Claude."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(api_key=self.api_key)

            system = None
            chat_messages = []
            for msg in messages:
                if msg.role == "system":
                    system = msg.content
                else:
                    chat_messages.append({"role": msg.role, "content": msg.content})

            response = await client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system or "You are a security analysis assistant.",
                messages=chat_messages,
            )

            return LLMResponse(
                content=response.content[0].text,
                model=self.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
            )

        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic") from None

    async def stream_chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream chat from Claude."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(api_key=self.api_key)

            system = None
            chat_messages = []
            for msg in messages:
                if msg.role == "system":
                    system = msg.content
                else:
                    chat_messages.append({"role": msg.role, "content": msg.content})

            async with client.messages.stream(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system or "You are a security analysis assistant.",
                messages=chat_messages,
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic") from None


class OpenAIClient(BaseLLMClient):
    """OpenAI GPT client."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o"):
        self.api_key = api_key or get_settings().openai_api_key
        self.model = model
        self.logger = get_logger("ai.openai")

        if not self.api_key:
            raise ValueError("OpenAI API key not configured. Set SECSUITE_OPENAI_API_KEY")

    async def chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat to GPT."""
        try:
            import openai

            client = openai.AsyncOpenAI(api_key=self.api_key)

            chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

            response = await client.chat.completions.create(
                model=self.model,
                messages=chat_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return LLMResponse(
                content=response.choices[0].message.content,
                model=self.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                },
            )

        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai") from None

    async def stream_chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream chat from GPT."""
        try:
            import openai

            client = openai.AsyncOpenAI(api_key=self.api_key)

            chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

            stream = await client.chat.completions.create(
                model=self.model,
                messages=chat_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )

            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai") from None


class OllamaClient(BaseLLMClient):
    """Ollama client for local LLMs (LLaMA, Qwen, Mistral, etc.)."""

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,  # Not used but kept for interface consistency
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.logger = get_logger("ai.ollama")

    async def chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat to Ollama."""
        import httpx

        chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": chat_messages,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            )

            if response.status_code != 200:
                raise Exception(f"Ollama error: {response.status_code} - {response.text}")

            data = response.json()

            return LLMResponse(
                content=data["message"]["content"],
                model=self.model,
                usage={
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0),
                },
            )

    async def stream_chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream chat from Ollama."""
        import httpx

        chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": chat_messages,
                    "stream": True,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            yield data["message"]["content"]


class OpenAICompatibleClient(BaseLLMClient):
    """Client for any OpenAI-compatible API (vLLM, LM Studio, LocalAI, etc.)."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = "not-needed",
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or "not-needed"
        self.logger = get_logger("ai.openai_compatible")

    async def chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat to OpenAI-compatible API."""
        try:
            import openai

            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )

            chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

            response = await client.chat.completions.create(
                model=self.model,
                messages=chat_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return LLMResponse(
                content=response.choices[0].message.content,
                model=self.model,
                usage={
                    "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) if response.usage else 0,
                    "completion_tokens": getattr(response.usage, "completion_tokens", 0) if response.usage else 0,
                },
            )

        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai") from None

    async def stream_chat(
        self,
        messages: list[Message],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream chat from OpenAI-compatible API."""
        try:
            import openai

            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )

            chat_messages = [{"role": msg.role, "content": msg.content} for msg in messages]

            stream = await client.chat.completions.create(
                model=self.model,
                messages=chat_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )

            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai") from None


# Pre-configured model shortcuts (maps shortcuts to actual ollama model names)
# These use base names that work with :latest tags
OLLAMA_MODELS = {
    "llama3": "llama3",
    "llama3.1": "llama3.1",
    "llama3.2": "llama3.2",
    "llama2": "llama2",
    "qwen": "qwen2.5",
    "qwen2": "qwen2",
    "qwen2.5": "qwen2.5",
    "mistral": "mistral",
    "mixtral": "mixtral",
    "codellama": "codellama",
    "deepseek": "deepseek-coder-v2",
    "phi": "phi3",
    "phi3": "phi3",
    "gemma": "gemma2",
    "gemma2": "gemma2",
}


def get_llm_client(
    provider: str = "anthropic",
    model: str | None = None,
    base_url: str | None = None,
    **kwargs
) -> BaseLLMClient:
    """Get LLM client by provider name.

    Args:
        provider: Provider name - "anthropic", "openai", "ollama", or "openai-compatible"
        model: Model name (optional, uses provider default)
        base_url: Base URL for API (required for openai-compatible, optional for ollama)
        **kwargs: Additional arguments for the client

    Supported providers:
        - anthropic/claude: Anthropic Claude API
        - openai/gpt: OpenAI API
        - ollama: Local Ollama server (LLaMA, Qwen, Mistral, etc.)
        - ollama/<model>: Ollama with specific model (e.g., "ollama/qwen2.5")
        - openai-compatible: Any OpenAI-compatible API (vLLM, LM Studio, etc.)

    Examples:
        get_llm_client("anthropic")
        get_llm_client("ollama", model="qwen2.5")
        get_llm_client("ollama/llama3.2")
        get_llm_client("openai-compatible", base_url="http://localhost:8000/v1", model="my-model")

    Returns:
        Configured LLM client
    """
    provider_lower = provider.lower()

    # Handle ollama/<model> syntax
    if provider_lower.startswith("ollama/"):
        model_name = provider_lower.split("/", 1)[1]
        # Map common names to actual model names
        model = OLLAMA_MODELS.get(model_name, model_name)
        return OllamaClient(
            model=model,
            base_url=base_url or "http://localhost:11434",
            **kwargs
        )

    # Standard provider mapping
    if provider_lower in ("anthropic", "claude"):
        client_kwargs = {"model": model} if model else {}
        client_kwargs.update(kwargs)
        return AnthropicClient(**client_kwargs)

    elif provider_lower in ("openai", "gpt"):
        client_kwargs = {"model": model} if model else {}
        client_kwargs.update(kwargs)
        return OpenAIClient(**client_kwargs)

    elif provider_lower == "ollama":
        return OllamaClient(
            model=model or "llama3.2",
            base_url=base_url or "http://localhost:11434",
            **kwargs
        )

    elif provider_lower in ("openai-compatible", "openai_compatible", "custom"):
        if not base_url:
            raise ValueError("base_url is required for openai-compatible provider")
        if not model:
            raise ValueError("model is required for openai-compatible provider")
        return OpenAICompatibleClient(
            base_url=base_url,
            model=model,
            **kwargs
        )

    # Check if it's a known ollama model shortcut
    elif provider_lower in OLLAMA_MODELS:
        return OllamaClient(
            model=OLLAMA_MODELS[provider_lower],
            base_url=base_url or "http://localhost:11434",
            **kwargs
        )

    else:
        available = "anthropic, openai, ollama, ollama/<model>, qwen, llama3, mistral, openai-compatible"
        raise ValueError(f"Unknown provider: {provider}. Available: {available}")


def list_supported_providers() -> dict:
    """List all supported LLM providers and models."""
    return {
        "cloud_providers": {
            "anthropic": "Claude models (claude-sonnet-4-20250514, etc.)",
            "openai": "OpenAI models (gpt-4o, gpt-4-turbo, etc.)",
        },
        "local_providers": {
            "ollama": "Local Ollama server - supports many open models",
            "openai-compatible": "Any OpenAI-compatible API (vLLM, LM Studio, LocalAI, etc.)",
        },
        "ollama_model_shortcuts": OLLAMA_MODELS,
        "usage_examples": [
            'get_llm_client("anthropic")',
            'get_llm_client("ollama", model="qwen2.5")',
            'get_llm_client("ollama/llama3.2")',
            'get_llm_client("qwen")  # shortcut for ollama/qwen2.5',
            'get_llm_client("openai-compatible", base_url="http://localhost:8000/v1", model="my-model")',
        ],
    }
