"""Reproducible local source identity; never reads credentials or raw traces."""

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
from pathlib import Path

from reef_panda_arena.application.comparison_contract import source_revision

ROOT = Path(__file__).resolve().parents[1]


def source_identity():
    paths = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT,
    ).decode().split('\0')
    files = {}
    for name in sorted(set(paths)):
        if not name:
            continue
        if name == '.env' or name.startswith(('.build/', '.git/')):
            raise ValueError('Private input unexpectedly included in public source inventory')
        path = ROOT / name
        if path.is_file():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'dirty_worktree': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
        'source_tree_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
        'implementation_sha256': source_revision(),
        'files': files,
    }


def hardware_info():
    cpu, memory = 'unknown', None
    cpuinfo, meminfo = Path('/proc/cpuinfo'), Path('/proc/meminfo')
    if cpuinfo.is_file():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith('model name'):
                cpu = line.split(':', 1)[1].strip()
                break
    if meminfo.is_file():
        for line in meminfo.read_text().splitlines():
            if line.startswith('MemTotal:'):
                memory = round(int(line.split()[1]) / 1024 / 1024, 1)
                break
    return {'cpu': cpu, 'logical_cpus': os.cpu_count(), 'ram_gib': memory,
            'python': platform.python_version(), 'platform': platform.platform()}


def runtime_versions():
    versions = {}
    for name in ('pydantic', 'SQLAlchemy', 'asyncmy', 'langgraph', 'cryptography'):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = 'not_installed'
    return versions
