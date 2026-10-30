"""Create local secrets, install the package, and start the private MySQL service."""

import base64
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import venv
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required")
    if shutil.which("docker") is None:
        raise SystemExit("Docker with the Compose plugin is required")
    run("docker", "compose", "version")
    env_path = ROOT / ".env"
    if not env_path.exists():
        app_password = secrets.token_urlsafe(32)
        root_password = secrets.token_urlsafe(32)
        encryption_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        db_url = (
            "mysql+asyncmy://arena_app:"
            f"{quote(app_password, safe='')}@localhost/reef_panda_arena?charset=utf8mb4"
        )
        contents = (
            "MYSQL_DATABASE=reef_panda_arena\n"
            "MYSQL_USER=arena_app\n"
            f"MYSQL_PASSWORD={app_password}\n"
            f"MYSQL_ROOT_PASSWORD={root_password}\n"
            f"ARENA_DATABASE_URL={db_url}\n"
            "ARENA_DATABASE_SOCKET=.mysql-socket/mysqld.sock\n"
            f"ARENA_ENCRYPTION_KEY_BASE64={encryption_key}\n"
            "ARENA_OLLAMA_URL=http://127.0.0.1:11434\n"
            "ARENA_MODEL=qwen3:1.7b\n"
            "ARENA_MAX_CONCURRENT_RUNS=2\n"
        )
        try:
            descriptor = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print("Using existing .env")
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as env_file:
                env_file.write(contents)
            print("Created private .env with generated local credentials")
    else:
        print("Using existing .env")
    (ROOT / ".mysql-socket").mkdir(exist_ok=True)
    venv_dir = ROOT / ".venv"
    python_path = venv_dir / "bin" / "python"
    if not python_path.is_file():
        venv.EnvBuilder(with_pip=True).create(venv_dir)
    python = str(python_path)
    run(python, "-m", "pip", "install", "pip>=26.2,<27")
    run(python, "-m", "pip", "install", "setuptools>=84.1,<85", "wheel>=0.44,<1")
    run(python, "-m", "pip", "install", "--no-build-isolation", "-e", ".[test,api,live]")
    run("docker", "compose", "up", "-d", "--wait", "mysql")
    run(str(venv_dir / "bin" / "reef-panda-arena"), "doctor")
    print("Ready: .venv/bin/reef-panda-arena scenarios list")


if __name__ == "__main__":
    main()
