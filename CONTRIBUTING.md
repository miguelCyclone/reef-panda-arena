# Contributing

Start with `agent.md`, `docs/ARCHITECTURE.md`, `docs/BENCHMARK.md`, and the Codex task sequence under `.build/` if you have the original blueprint archive.

Contributions should be small and independently testable: a scenario with deterministic decoder, a gateway policy, a mock tool, a metric, or a bug fix. Run one benign and one attacked replay case whenever a boundary changes. Add **only purposeful tests**.

All data must be synthetic. Do not add external exfiltration URLs, real API keys, execution shells, or third-party datasets with incompatible terms. Keep files cohesive and ordinarily under ~600 lines. Avoid writing migrations: update `migration/schema.sql` as the single canonical schema for a development reset.

Run `ARENA_TEST_MYSQL=1 .venv/bin/python -m pytest -q` and `node --test tests/test_web.mjs` after browser or boundary changes.

Before opening a PR, state what is implemented versus specified, which scenarios you ran, model/seed if relevant, and known limitations. No exaggerated claims of covert-channel prevention.

## Standalone package check

Build into an empty directory and verify the wheel outside the checkout:

```bash
.venv/bin/python -m pip wheel --no-deps --no-build-isolation . --wheel-dir /tmp/reef-panda-wheel
.venv/bin/python tools/check_wheel.py /tmp/reef-panda-wheel
```

The checker requires exactly one Reef Panda wheel and verifies all 44 library cases, booking contracts, fixtures, browser assets and the single schema.
