"""Local application configuration."""

import base64
from pathlib import Path

from pydantic import SecretStr
from sqlalchemy.engine import URL, make_url
from pydantic_settings import BaseSettings, SettingsConfigDict


class ArenaSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ARENA_", extra="ignore"
    )

    database_url: SecretStr
    database_socket: Path | None = None
    encryption_key_base64: SecretStr | None = None
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen3:1.7b"
    max_concurrent_runs: int = 2

    @property
    def sqlalchemy_url(self) -> URL:
        url = make_url(self.database_url.get_secret_value())
        if url.drivername != "mysql+asyncmy":
            raise ValueError("ARENA_DATABASE_URL must use the mysql+asyncmy driver")
        if self.database_socket is not None:
            socket_path = self.database_socket.expanduser().resolve()
            return url.set(query={**url.query, "unix_socket": str(socket_path)})
        return url

    @property
    def encryption_key(self) -> bytes:
        if self.encryption_key_base64 is None:
            raise ValueError("ARENA_ENCRYPTION_KEY_BASE64 is required for runs")
        try:
            key = base64.b64decode(
                self.encryption_key_base64.get_secret_value(), validate=True
            )
        except ValueError as error:
            raise ValueError("ARENA_ENCRYPTION_KEY_BASE64 is invalid") from error
        if len(key) != 32:
            raise ValueError("ARENA_ENCRYPTION_KEY_BASE64 must decode to 32 bytes")
        return key
