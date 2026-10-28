"""Check public source for common credential formats and accidental private files."""

from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = (
    "src", "tests", "tools", "docs", "scenarios", "fixtures", "migration",
    ".github",
)
PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
)
TEXT_SUFFIXES = {".py", ".md", ".txt", ".sql", ".yaml", ".yml", ".toml", ".csv", ".json", ".sh", ".js", ".mjs", ".css", ".html"}


def main() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "--cached"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.splitlines()
    forbidden = [
        path for path in tracked
        if path == ".env" or path.startswith((".build/", ".mysql-socket/", "local-traces/"))
    ]
    if forbidden:
        raise SystemExit(f"Private paths are tracked: {', '.join(forbidden)}")
    paths = [ROOT / name for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "compose.yml", "pyproject.toml", ".env.example")]
    for directory in PUBLIC:
        base = ROOT / directory
        if base.exists():
            paths.extend(path for path in base.rglob("*") if path.is_file() and path.suffix in TEXT_SUFFIXES)
    findings = []
    for path in paths:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            if any(pattern.search(content) for pattern in PATTERNS):
                findings.append(str(path.relative_to(ROOT)))
    if findings:
        raise SystemExit(f"Credential-like text found in: {', '.join(findings)}")
    print(f"Secret scan passed: {len(paths)} public text files")


if __name__ == "__main__":
    main()
