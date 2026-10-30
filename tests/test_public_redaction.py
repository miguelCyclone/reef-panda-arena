"""Actual accepted encodings remain private across persisted public transports."""

import asyncio
import base64
from contextlib import redirect_stdout
import io
import json
import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.application.unified import run_unified_replay
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.gateway.invoke import PolicyGateway
from reef_panda_arena.scenarios.channels import codebook
from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, SyntheticVault


def forms(value):
    result = {value.hex(), base64.b64encode(value).decode(), base64.urlsafe_b64encode(value).decode()}
    try:
        result.add(value.decode('ascii'))
    except UnicodeDecodeError:
        pass
    result.add(json.dumps(list(value)))
    result.add(','.join(map(str, value)))
    return {item for item in result if len(item) >= 8}


def test_mysql_public_surfaces_exclude_markers_encodings_receiver_keys_and_maps(monkeypatch):
    if os.getenv('ARENA_TEST_MYSQL') != '1':
        pytest.skip('Set ARENA_TEST_MYSQL=1 for real persisted redaction acceptance')

    async def verify():
        settings = ArenaSettings().model_copy(update={'fixture_mode': 'key_derived_unknown'})
        manager = RunManager(settings)
        engine = create_async_engine(settings.sqlalchemy_url)
        created, confidential = [], set()
        confidential.update(forms(settings.encryption_key))
        registry = ExtensionFixtureRegistry()
        confidential.add(json.dumps(registry.data['basis_vectors']))
        confidential.add(json.dumps(codebook(31), sort_keys=True))
        confidential.add(json.dumps({v: k for k, v in codebook(31).items()}, sort_keys=True))
        confidential.update(forms(SensitiveFixtureRegistry().load('C14', 31, settings.encryption_key).fixture_key))
        confidential.update(forms(registry.load('C21', 31, settings.encryption_key).fixture_key))
        original = PolicyGateway.invoke
        def collect(value):
            if isinstance(value, dict):
                for name, item in value.items():
                    if name in {'ciphertext_b64', 'nonce_b64'} and isinstance(item, str):
                        confidential.add(item)
                    if name in {'coefficients', 'basis_values', 'byte_values', 'values'} and isinstance(item, list):
                        confidential.add(json.dumps(item))
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)
        async def invoke(gateway, context, call):
            collect(call.arguments)
            return await original(gateway, context, call)
        monkeypatch.setattr(PolicyGateway, 'invoke', invoke)
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(settings, manager)), base_url='http://testserver') as client:
                for sid in ('C01', 'C06', 'C13', 'C14', 'C17', 'C21', 'C24', 'C32'):
                    run_id = str(uuid4())
                    created.append(run_id)
                    runner = run_unified_replay if sid == 'C32' else run_replay
                    await runner(sid, 'allowlist_only' if sid == 'C32' else 'none', 31,
                                 settings=settings, run_id=run_id)
                    async with async_sessionmaker(engine)() as session:
                        stored = (await session.scalars(select(SyntheticVault).where(SyntheticVault.run_id == run_id))).all()
                        assert stored
                        for item in stored:
                            marker = SyntheticSecretVault(settings.encryption_key).decrypt(item)
                            confidential.update(forms(marker))
                            if sid == 'C06':
                                confidential.add(' '.join(codebook(31)[char] for char in marker.decode()))
                    public = []
                    for suffix in ('', '/report', '/events', '/lineage', '/stream'):
                        response = await client.get(f'/v1/runs/{run_id}{suffix}')
                        assert response.status_code == 200
                        public.append(response.text)
                        if suffix == '/stream':
                            assert 'run.completed' in response.text
                    if sid == 'C32':
                        public.append((await client.get(f'/v1/runs/{run_id}/unified-report')).text)
                    buffer = io.StringIO()
                    with redirect_stdout(buffer):
                        await _export_csv(settings, run_id)
                    public.append(buffer.getvalue())
                    # Normalize JSON whitespace without decoding or displaying any private values.
                    text = ''.join(public).replace(' ', '')
                    matches = sum(value.replace(' ', '') in text for value in confidential if value)
                    assert matches == 0, 'Confidential representation escaped a public transport'
        finally:
            await manager.shutdown()
            async with async_sessionmaker(engine)() as session, session.begin():
                await session.execute(delete(ArenaRun).where(ArenaRun.id.in_(created)))
            await engine.dispose()
    asyncio.run(verify())
