"""Measure a small matched replay matrix; stdout is safe Markdown."""

import argparse
import asyncio
import hashlib
import platform
from pathlib import Path



ROOT = Path(__file__).resolve().parents[1]


def source_digest() -> str:
    paths = [
        *sorted((ROOT / "src").rglob("*.py")),
        *sorted((ROOT / "scenarios").glob("*.yaml")),
        ROOT / "scenarios" / "catalog.csv",
        ROOT / "fixtures" / "shipping_task.json",
        ROOT / "migration" / "schema.sql",
    ]
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def hardware() -> tuple[str, str]:
    cpu = platform.processor() or "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    memory = "unknown"
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = f"{int(line.split()[1]) / 1024**2:.1f} GiB"
                break
    return cpu, memory


def ratio(count: int, total: int) -> str:
    return f"{count}/{total}"


async def measure(seeds: tuple[int, ...]) -> None:
    """Use the audited study runner; retain failed trials and measured denominators."""
    from uuid import uuid4
    from benchmark_post_audit import study
    from benchmark_matrix_evidence import render_matrix

    output = ROOT / ".build/measurements" / f"legacy-replay-{uuid4().hex}"
    plan, rows = await study(tuple(f"C{i:02}" for i in range(10)), seeds, output)
    print(render_matrix(plan, rows))
    print(f"Saved per-trial evidence and provenance to {output}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[31, 32, 33])
    args = parser.parse_args()
    if len(set(args.seeds)) != len(args.seeds) or any(not 0 <= seed < 2**64 for seed in args.seeds):
        parser.error("seeds must be distinct unsigned 64-bit integers")
    asyncio.run(measure(tuple(args.seeds)))


if __name__ == "__main__":
    main()
