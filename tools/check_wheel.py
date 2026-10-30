"""Check that a built wheel runs its finite scenarios outside the checkout."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel_dir", type=Path)
    args = parser.parse_args()
    wheels = sorted(args.wheel_dir.glob("reef_panda_arena-*.whl"))
    if len(wheels) != 1:
        parser.error("Expected exactly one Reef Panda wheel")
    with TemporaryDirectory(prefix="reef-wheel-check-") as temporary:
        extracted = Path(temporary)
        with ZipFile(wheels[0]) as archive:
            archive.extractall(extracted)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(extracted)
        check = """
from pathlib import Path
import reef_panda_arena
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
package = Path(reef_panda_arena.__file__).resolve()
assert package.is_relative_to(Path.cwd()), package
loader = ScenarioLoader()
assert loader.root == package.parent / 'data'
assert len(loader.list_ids()) == 44
for scenario_id in loader.list_ids():
    assert loader.load(scenario_id).id == scenario_id
assert loader.shipping_fixture()['synthetic_only'] is True
assert len(SensitiveFixtureRegistry().seeds) == 22
assert len(ExtensionFixtureRegistry().seeds) == 22
adaptive = AdaptiveFixtureRegistry()
assert len(adaptive.development_seeds) == 5
assert len(adaptive.holdout_seeds) == 5
assert (package.parent / 'web' / 'index.html').is_file()
for asset in ('flow-model.js', 'flow-graph.js', 'flow-player.js', 'flow.css', 'booking.html', 'booking.css', 'booking.js'):
    assert (package.parent / 'web' / asset).is_file()
from reef_panda_arena.application.booking_contract import BookingConfig
from reef_panda_arena.scenarios.booking import booking_fixture
from reef_panda_arena.oracle.booking import booking_utility, decode_booking
import json
assert BookingConfig().arm == 'A0'
fixture = booking_fixture(b'w'*32, 31, 0)
payload = json.dumps(fixture.authorized_output()).encode()
assert booking_utility((payload,), fixture.authorized_output())
assert decode_booking(payload, fixture.receiver, 'text').value is None
from reef_panda_arena.telemetry.visual_catalog import describe_scenario
assert all(describe_scenario(loader.load(sid)).mechanisms for sid in loader.list_ids())
assert (package.parent / 'data' / 'migration' / 'schema.sql').is_file()
assert (package.parent / 'data' / 'contracts' / 'unified_run_report.schema.json').is_file()
assert (package.parent / 'data' / 'contracts' / 'unified_scenario.schema.json').is_file()
print('Wheel runtime corpus passed: core booking, 44 library scenarios, adaptive 5+5 seeds, schemas, browser assets')
"""
        subprocess.run(
            [sys.executable, "-c", check], cwd=extracted, env=environment,
            check=True,
        )


if __name__ == "__main__":
    main()
