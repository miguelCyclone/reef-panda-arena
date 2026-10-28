# Contributing

Start with `agent.md`, `docs/ARCHITECTURE.md`, `docs/BENCHMARK.md`, and the Codex task sequence under `.build/` if you have the original blueprint archive.

Contributions should be small and independently testable: a scenario with deterministic decoder, a gateway policy, a mock tool, a metric, or a bug fix. Run one benign and one attacked replay case whenever a boundary changes. Add **only purposeful tests**.

All data must be synthetic. Do not add external exfiltration URLs, real API keys, execution shells, or third-party datasets with incompatible terms. Keep files cohesive and ordinarily under ~600 lines. Avoid writing migrations: update `migration/schema.sql` as the single canonical schema for a development reset.

Before opening a PR, state what is implemented versus specified, which scenarios you ran, model/seed if relevant, and known limitations. No exaggerated claims of covert-channel prevention.
