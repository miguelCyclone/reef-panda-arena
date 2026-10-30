"""Generate redacted API traces for full-catalog visual verification, locally."""

import asyncio
import json
from pathlib import Path

import httpx

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.settings import ArenaSettings


async def main():
    settings = ArenaSettings()
    manager = RunManager(settings)
    output = Path('.build/visualization')
    output.mkdir(parents=True, exist_ok=True)
    traces = []
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(settings, manager)), base_url='http://local') as client:
            response = await client.get('/v1/scenarios')
            response.raise_for_status()
            scenarios = response.json()
            cases = [(s['id'], 'allowlist_only' if int(s['id'][1:]) >= 29 else 'none', True) for s in scenarios]
            cases += [('C03', 'taint', True), ('C32', 'transitive', True), ('C00', 'none', False), ('C18', 'taint', True), ('C40', 'actor_local', True)]
            for sid, defense, attack in cases:
                created = await client.post('/v1/runs', json={
                    'scenario_id': sid, 'mode': 'replay', 'defense_profile': defense,
                    'seed': 31, 'attack_enabled': attack,
                })
                created.raise_for_status()
                rid = created.json()['run_id']
                job = manager._jobs.get(rid)
                if job is not None and job.task is not None:
                    await job.task
                status = (await client.get(f'/v1/runs/{rid}')).json()
                assert status['status'] == 'completed', status
                report = (await client.get(f'/v1/runs/{rid}/report')).json()
                events = []
                cursor = 0
                for _ in range(2):
                    page = (await client.get(f'/v1/runs/{rid}/events?cursor={cursor}&limit=100')).json()
                    events.extend(page['events'])
                    if page['next_cursor'] is None:
                        break
                    cursor = page['next_cursor']
                assert events[-1]['event'] == 'run.completed'
                traces.append({'scenario': next(s for s in scenarios if s['id'] == sid), 'status': status, 'report': report, 'events': events})
                print(f"Verified {sid} / {defense} / attack={attack}", flush=True)
    finally:
        await manager.shutdown()
    (output / 'traces.json').write_text(json.dumps(traces, indent=2) + '\n')
    print(f'Saved {len(traces)} redacted visual traces to {output}')


if __name__ == '__main__':
    asyncio.run(main())
