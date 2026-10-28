"""Loopback-only Ollama adapter; models can propose but never execute tools."""

import json
from urllib.parse import urlparse

import httpx

from reef_panda_arena.gateway.invoke import ProposedCall
from reef_panda_arena.model.protocol import ModelRequest, ModelResult
from reef_panda_arena.tools.registry import TOOL_INPUTS


class ModelUnavailable(RuntimeError):
    pass


class ModelOutputError(ValueError):
    pass


class OllamaCaller:
    def __init__(self, base_url: str = "http://127.0.0.1:11434") -> None:
        parsed = urlparse(base_url)
        if (parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1", "localhost", "::1"
        } or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment):
            raise ValueError("Ollama URL must be a local HTTP loopback endpoint")
        self.base_url = base_url.rstrip("/")

    async def complete(self, request: ModelRequest) -> ModelResult:
        alias_to_name = {name.replace(".", "_"): name for name in request.tool_names}
        if any(name not in TOOL_INPUTS for name in request.tool_names):
            raise ValueError("Unknown model tool schema")
        tools = [
            {
                "type": "function",
                "function": {
                    "name": alias,
                    "description": f"Local synthetic {canonical} tool",
                    "parameters": TOOL_INPUTS[canonical].model_json_schema(),
                },
            }
            for alias, canonical in alias_to_name.items()
        ]
        payload = {
            "model": request.config.model_name,
            "messages": [message.model_dump() for message in request.messages],
            "tools": tools,
            "stream": False,
            "think": request.config.model_name.startswith("qwen3:4b"),
            "options": {
                "temperature": request.config.temperature,
                "num_predict": request.config.max_response_tokens,
                "num_ctx": 4096,
            },
        }
        if request.output_schema is not None:
            payload["format"] = request.output_schema
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=request.config.timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.post("/api/chat", json=payload)
                response.raise_for_status()
        except (httpx.HTTPError, httpx.TimeoutException) as error:
            raise ModelUnavailable("Local Ollama request failed") from error
        if len(response.content) > 65536:
            raise ModelOutputError("Model response exceeded size limit")
        try:
            data = response.json()
            message = data["message"]
            content = message.get("content") or ""
            if not isinstance(content, str) or len(content) > 8192:
                raise ModelOutputError("Invalid model content")
            raw_calls = message.get("tool_calls") or []
            if not isinstance(raw_calls, list) or len(raw_calls) > 4:
                raise ModelOutputError("Invalid model tool-call count")
            calls = []
            for raw in raw_calls:
                function = raw["function"]
                alias = function["name"]
                arguments = function["arguments"]
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                if not isinstance(alias, str) or not isinstance(arguments, dict):
                    raise ModelOutputError("Invalid model tool call")
                calls.append(ProposedCall(
                    tool_name=alias_to_name.get(alias, alias), arguments=arguments,
                ))
            if not calls and content.lstrip().startswith("{"):
                try:
                    parsed = ProposedCall.model_validate_json(content)
                    calls = [ProposedCall(
                        tool_name=alias_to_name.get(parsed.tool_name, parsed.tool_name),
                        arguments=parsed.arguments,
                    )]
                except ValueError:
                    pass
            model_name = data.get("model") or request.config.model_name
            return ModelResult(
                content=content, proposed_calls=tuple(calls), model_name=model_name,
            )
        except (KeyError, TypeError, json.JSONDecodeError, ValueError) as error:
            raise ModelOutputError("Local model returned an invalid response") from error

    async def model_digest(self, model_name: str) -> str | None:
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=5.0, trust_env=False,
            ) as client:
                response = await client.get("/api/tags")
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise ModelUnavailable("Local Ollama model list unavailable") from error
        for item in data.get("models", []):
            if item.get("name") == model_name:
                digest = item.get("digest")
                return digest if isinstance(digest, str) else None
        return None
