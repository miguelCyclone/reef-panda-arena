"""Declared modes agree with HTTP exposure and actual CLI runner selection."""

import asyncio
import importlib
from types import SimpleNamespace

import httpx
import pytest
import yaml
from pydantic import ValidationError

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.scenarios.loader import ScenarioDefinition, ScenarioLoader
from reef_panda_arena.settings import ArenaSettings


def modes_for(index):
    return (("replay", "live") if index == 0 else
            ("replay",) if index < 22 else
            ("replay", "live_adaptive") if index < 29 else
            ("replay", "live_multiagent"))


def test_manifest_http_and_cli_modes_match_executable_dispatch(monkeypatch, capsys):
    cli = importlib.import_module("reef_panda_arena.cli.main")
    invoked = []
    def runner(name):
        async def run(*args, **kwargs):
            invoked.append((name, args[0]))
            return SimpleNamespace(run_id="dispatch-only")
        return run
    for module, symbol, name in (
        (cli, "run_replay", "legacy_replay"),
        (importlib.import_module("reef_panda_arena.application.live"), "run_live", "live"),
        (importlib.import_module("reef_panda_arena.application.adaptive"), "run_adaptive", "adaptive"),
        (importlib.import_module("reef_panda_arena.application.unified"), "run_unified_replay", "unified_replay"),
        (importlib.import_module("reef_panda_arena.application.unified"), "run_unified_live", "live_multiagent"),
    ):
        monkeypatch.setattr(module, symbol, runner(name))
    async def reports(*args, **kwargs):
        return [{"run_id": "dispatch-only"}]
    monkeypatch.setattr(cli, "list_reports", reports)
    loader = ScenarioLoader()
    for i in range(44):
        sid = f"C{i:02}"
        assert loader.load(sid).mode_support == modes_for(i)
        for mode in ("replay", "live", "live_adaptive", "live_multiagent"):
            before = len(invoked)
            monkeypatch.setattr("sys.argv", ["reef-panda-arena", "run", sid, "--mode", mode])
            if mode not in modes_for(i):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 1 and len(invoked) == before
            else:
                cli.main()
                expected = ("live_multiagent" if mode == "live_multiagent" else
                            "unified_replay" if i >= 29 else "adaptive" if i >= 22 else
                            "live" if mode == "live" else "legacy_replay")
                assert invoked[before:] == [(expected, sid)]
            capsys.readouterr()

    async def verify_http():
        settings = ArenaSettings()
        manager = RunManager(settings)
        app = create_app(settings, manager)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            rows = (await client.get("/v1/scenarios")).json()
            assert len(rows) == 44
            for row in rows:
                i = int(row["id"][1:])
                assert tuple(row["available_modes"]) == modes_for(i)
                for mode in set(("replay", "live", "live_adaptive", "live_multiagent")) - set(modes_for(i)):
                    result = await client.post("/v1/runs", json={"scenario_id": row["id"], "mode": mode,
                        "defense_profile": "transitive" if i >= 29 else "none", "seed": 31})
                    assert result.status_code == 422, result.text
            assert not manager._jobs
        await manager.shutdown()
    asyncio.run(verify_http())


def test_unsupported_live_manifest_is_rejected_before_exposure():
    loader = ScenarioLoader()
    raw = yaml.safe_load((loader.root / "scenarios/C01.yaml").read_text())
    raw["mode_support"] = ["replay", "live"]
    with pytest.raises(ValidationError, match="Declared modes"):
        ScenarioDefinition.model_validate(raw)
