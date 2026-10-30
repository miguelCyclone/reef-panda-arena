"""Find the canonical checkout corpus or the read-only corpus bundled in a wheel."""

from pathlib import Path


def default_data_root() -> Path:
    source_root = Path(__file__).resolve().parents[3]
    package_root = Path(__file__).resolve().parents[1] / "data"
    for root in (source_root, package_root):
        if ((root / "scenarios" / "catalog.csv").is_file()
                and (root / "fixtures" / "shipping_task.json").is_file()
                and (root / "fixtures" / "sensitive_cases.json").is_file()
                and (root / "fixtures" / "extension_cases.json").is_file()
                and (root / "fixtures" / "adaptive_cases.json").is_file()):
            return root
    raise FileNotFoundError("Reef Panda scenario and fixture corpus is missing")
