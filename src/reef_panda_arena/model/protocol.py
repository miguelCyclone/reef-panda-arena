"""Provider-independent bounded model request and result contracts."""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from reef_panda_arena.gateway.invoke import ProposedCall


class ModelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(max_length=8192)


class ModelConfig(BaseModel):
    model_name: str = Field(min_length=1, max_length=160)
    temperature: float = Field(ge=0, le=1)
    max_response_tokens: int = Field(ge=1, le=1024)
    timeout_seconds: float = Field(ge=1, le=120)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    messages: tuple[ModelMessage, ...] = Field(min_length=1, max_length=12)
    tool_names: tuple[str, ...] = Field(default=(), max_length=8)
    output_schema: dict | None = None
    config: ModelConfig


class ModelResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    content: str = Field(max_length=8192)
    proposed_calls: tuple[ProposedCall, ...] = Field(max_length=4)
    model_name: str = Field(min_length=1, max_length=160)


class ModelCaller(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResult: ...
