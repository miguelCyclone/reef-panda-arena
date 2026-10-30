"""Copy the finite, public runtime corpus into built wheels from its root source."""

import csv
import re
from pathlib import Path
from shutil import copy2

from setuptools import setup
from setuptools.command.build_py import build_py


ROOT = Path(__file__).resolve().parent
def runtime_files() -> tuple[Path, ...]:
    catalog = Path("scenarios/catalog.csv")
    with (ROOT / catalog).open(newline="", encoding="utf-8") as source:
        scenario_ids = [row["scenario_id"] for row in csv.DictReader(source)]
    if len(set(scenario_ids)) != len(scenario_ids) or any(
        re.fullmatch(r"C[0-9]{2}", scenario_id) is None for scenario_id in scenario_ids
    ):
        raise ValueError("Invalid scenario catalog for package build")
    return (
        catalog,
        *(Path("scenarios") / f"{scenario_id}.yaml" for scenario_id in scenario_ids),
        Path("fixtures/shipping_task.json"),
        Path("fixtures/sensitive_cases.json"),
        Path("fixtures/extension_cases.json"),
        Path("fixtures/adaptive_cases.json"),
        Path("migration/schema.sql"),
        Path("contracts/unified_run_report.schema.json"),
        Path("contracts/unified_scenario.schema.json"),
    )


class BuildWithRuntimeCorpus(build_py):
    def run(self) -> None:
        super().run()
        for relative in runtime_files():
            source = ROOT / relative
            if not source.is_file():
                raise FileNotFoundError(f"Missing runtime corpus file: {relative}")
            destination = Path(self.build_lib) / "reef_panda_arena" / "data" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy2(source, destination)


setup(cmdclass={"build_py": BuildWithRuntimeCorpus})
