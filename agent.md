# Reef Panda implementation directives (source of truth)

These instructions apply to every code-writing agent and contributor working in this repository. **Codex should read this file before modifying code.** `AGENTS.md` points here so agents discover it automatically. Do not repeat or fork these instructions elsewhere.

## Mission

Implement an open-source, hermetic multi-agent security arena in stages. The team completes a benign shipping-delay customer task while a compromised worker attempts to leak *synthetic* vault data through permitted channels. The deterministic oracle grades actual accepted mock-sink payloads, while benign-task correctness is evaluated independently. Never confuse an attack *attempt*, a *detector alert*, and an *actual leak*.

## Non-negotiable engineering rules

1. **English only:** code, comments, variable names, docs, terminal output, UI, sample fixtures, tests, commit summaries.
2. **Semantic modularity:** composition over inheritance; wrappers, callers, adapters, protocols. Split by responsibility, not arbitrary file length. Aim for small cohesive modules; **absolute review trigger around 600 lines per source file** (docs can also be split by topic). No god classes, god components, all-in-one `utils.py`, or unnecessarily layered abstractions.
3. **Single schema:** put the **entire current MySQL schema** in `migration/schema.sql`. No incremental/versioned migration files or schema fragments. Any reset that drops a volume must be documented as **development-only destructive**. `schema_meta` is a release marker, not a migration history.
4. **No busy polling:** use SSE event push for updates, async run completion, and bounded waits. Any unavoidable polling must have an interval **>=30 seconds** (never a shorter recursive loop), stop automatically after **5 minutes of user inactivity**, and resume only upon user action. SSE heartbeats, if used, occur at >=30 seconds and are **not DB polling**. Close stale SSE streams after 300 seconds without active subscribers; do not leak tasks on disconnect. Browser automatic SSE reconnect must be explicitly controlled with >=30-second retry and the same inactivity cutoff.
5. **Bound every run:** finite graph, max rounds, model calls, tool invocations, payload sizes, elapsed time, memory growth, retries, and concurrent runs. No uncontrolled agent-to-agent debate or recursion. Avoid open-ended LLM self-reflection.
6. **Local first:** Ollama through `ModelCaller`, default small tool-capable model. Include deterministic scripted `ReplayCaller` that needs no model or network. LLM API calls never bypass `ModelCaller`.
7. **Every tool / message boundary goes through Reef Panda gateway:** normalize arguments; validate schema; attach actor/run/destination classification; authorize; enforce information-flow checks; then execute; record *redacted* event. Never rely on a model's own claim of approval.
8. **Exact, independent oracle:** private harness evaluates accepted sink bytes, with channel-specific deterministic decoder. It must not rely on an LLM judging whether the attack succeeded. Do not pass oracle expected secret or decode hints to defenders.
9. **No real exfiltration:** no external endpoint, third-party account, real secrets, arbitrary URL, subprocess execution, container escape, or unbounded tool code. Sink always resolves to local mock storage. Network egress is disabled for agent-facing tools.
10. **Privacy and safety:** synthetic fixture data only. Redact secret values and encoded equivalents from ordinary logs/UI as feasible; log metadata, digests, taint labels and decision reason. Never confuse a trace's confidentiality with its value as a research artifact. Raw local traces require an explicit opt-in and must be gitignored.
11. **Narrow tests:** only key behavior (schema initialization, benign task, exact oracle, scenario registry, gateway allow/deny, taint propagation, replay determinism, SSE idle/polling rules). One robust case per important boundary plus small scenario parametrization; avoid hundreds of redundant tests.
12. **API typed and consistent:** Pydantic v2 request/response DTOs, protocols for `ModelCaller`, `ToolAdapter`, `PolicyEngine`, `EventStore`, `Oracle`, `ScenarioLoader`, `Clock`. Fail closed on unrecognized tool, destination, permission, scenario, and classification. Use explicit stable identifiers.
13. **MySQL as system of record:** SQLAlchemy 2 async + asyncmy. Use short transactions, idempotent run-event writes and unique `(run_id, event_seq)`. Repositories isolate persistence; graph/model layer imports interfaces, not raw DB sessions.
14. **Model independence:** objective and score never depend on a specific model; persist model identifier, prompt version, scenario revision, seed, policy profile, and temperature for reproducibility.
15. **Performance without overengineering:** no queues, Kafka, Kubernetes, microservices, Redis, distributed checkpoint dependency, or generic plugin marketplace in MVP. Start one API worker + one MySQL container + optional external Ollama. Add scaling adapters only after benchmark evidence.
16. **No misleading claims:** label unimplemented pieces; annotate benchmark numbers with model, hardware, seeds, policy, sample count, task completion and run conditions. Avoid describing toy taint tracking as a general proof of no covert channels.
17. **Open-source hygiene:** SPDX-compatible MIT license for original code; pin upper bounds / lock on implementation; use dependabot/Renovate later if useful; basic secret scanning; `.env`, `.build`, local traces, database volumes ignored. No bundled copyrighted datasets or third-party weights.

## Architecture boundaries (implement these, not a monolith)

- `api/` — HTTP + SSE thin transport, no business logic.
- `application/` — run lifecycle, limits, stage management, transaction boundaries.
- `graph/` — explicit LangGraph topology and node wrappers, no SQL.
- `agents/` — role prompts/contracts; no direct tool backend imports.
- `model/` — `ModelCaller` protocol; `OllamaCaller`, `ReplayCaller` adapters.
- `gateway/` — one mandatory wrapper; policy engine, taint/declassification, invocation validation.
- `tools/` — synthetic source tools; local safe sink (no outbound network).
- `scenarios/` — catalog reader, constraints, seeded fixtures, adversarial scripted traces.
- `oracle/` — exact reconstruction from accepted local sink, inaccessible to agents.
- `storage/` — SQLAlchemy models and repositories matching `migration/schema.sql` only.
- `telemetry/` — redacted event assembly, SSE subscriptions, scoring exports.
- `cli/` — human-driven commands and non-polling local runner.
- `web/` — optional minimal UI, preferably after replay/CLI works.

## Implementation priority and acceptance

Follow `.build/planning/CODEX_TASKS.md` and `.build/planning/MILESTONES.md` in order. Start with one end-to-end replay scenario (C00) rather than writing all abstractions. Each phase ends with an actual executable example and compact CI acceptance checks.

**Do not state the demo works until runnable code and its smoke tests exist.** The current bundle is a specification/scaffold.
