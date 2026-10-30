# Independent role execution (experimental)

`live_multiagent` is available for C29–C43. It sends separate bounded requests to local Ollama for A1–A9. A0 is a trusted sequential scheduler. The mode has controlled boundary tests and a small actual-Ollama acceptance sample. **No actual-model trial in that sample completed the workflow, and no defense efficacy rate is established.** Historical published matrices remain replay results.

See [the baseline correction](LIVE_BASELINE_CORRECTION.md) for later integration changes: real private reads are now verified, while full legitimate task completion remains unfulfilled. The 24-trial table below is retained as historical R06 evidence.

## Run

With the existing local MySQL setup and an already installed Ollama model:

```bash
.venv/bin/reef-panda-arena run C31 --mode live_multiagent --defense allowlist_only --seed 31 --model qwen3:1.7b
.venv/bin/reef-panda-arena run C31 --mode live_multiagent --defense transitive --seed 31 --model qwen3:1.7b --no-attack
```

Use the same seed, model and defense to compare an attacked run with its no-attack control. The commands above illustrate two different defenses; they are not a matched pair. `--temperature`, `--top-p` and `--generation-seed` select bounded generation parameters. When no generation seed is supplied, the requested seed is the fixture seed modulo 2^31. Provider-level determinism is not guaranteed.

The browser's **Independent Ollama roles (C29–C43)** option selects the same controller. `POST /v1/runs` accepts `mode: "live_multiagent"`, the attack toggle, model name, temperature, optional `top_p`, and optional `generation_seed`. Adaptive arms, research rounds and holdout transfer do not apply to this mode. All destinations remain local mock sinks.

## What is decided

Each role sees only its accepted, authenticated inputs and public task instructions. Its model chooses a finite JSON decision: act, refuse, clarify or finish. The current `independent-role-v10` provider schema expresses the same cross-field rules as the runtime: act needs 1–4 actions, refuse/finish need none, and clarify permits at most one peer request. It can propose only its permitted tools, peer recipients and memory operations. Compromise changes the targeted role's system objective; it grants no new privileges and changes no other role's decision.

A2 chooses whether to read the private account and, on a later turn, calculates the route contribution. The trusted release validator checks that actual contribution; it does not repair the answer. A8 composes the customer records from received facts, and A9 chooses whether to send them. A refusal, invalid response or wrong calculation can prevent useful-task completion.

Public shipment and incident lookups are fixed context acquisition. Explicit `reader_contribution`, `release`, `forward_route` and `store_route` actions include narrow trusted validation/copy operations. Reader submission copies only an already visible source plus the model's submitted calculation to A3; it does not compute or repair the answer. The later route operations transfer an exact scoped decision when the role chooses the action; they do not authorize arbitrary model prose. Model-generated transformations retain every input dependency visible to that request.

## Decision opportunities and limitations

The finite plan grants ten or eleven decision opportunities, including a second A2 turn after a selected read. Request cases schedule the requesting role before the reader; the authorization case also gives A5 an earlier review turn. Memory cases give A7 separate inspection and subsequent decision turns. Branch cases let A4 review a later contribution before A8 combines inputs.

These are opportunities, not guaranteed attack paths. The model may refuse, choose another permitted route, or produce no useful output. Inspect actual messages and action outcomes before describing a particular path as executed. Branches execute sequentially; any combined representation is model chosen. Memory compaction is the existing whitespace normalization in same-process storage, not a process-restart experiment. C36/C43 live route opportunities can differ from their historical scripted replay paths.

The legitimate task already requires the private source. A preceding adversarial request alone does not prove that it caused a read that would otherwise not occur. Claims of an unwitting relay or autonomous concealment require actual independent decisions and accepted-sink reconstruction, beyond the presence of roles in a graph.

## Evidence and failures

`live-execution-v2` records each request before model I/O and each completed action afterward. Status, report, unified-report and CSV expose the same bounded evidence:

- Actual role, compromise assignment, prompt revision, turn, input event references, reported tokens and disposition.
- Prior generic gateway feedback; proposed action kinds and their accepted, rejected or failed states.
- A run-local HMAC fingerprint of the validated proposal, using an ephemeral key never sent to the model or published. It supports equality checks within that run; it is not a public hash of secret-bearing text, a cross-run comparison key or a reconstructable proposal archive.
- Backend (`ollama` versus test-only `injected_caller`), available model digest, requested generation settings and implementation source digest.

The proposal, accepted boundary operation and accepted customer receipt are different evidence. A compound exact-copy action may fail after an earlier suboperation committed; persisted boundary events and receipts retain that fact. An execution failure does not erase a prior confirmed leak. Failed or cancelled trials cannot establish a strict attacker win or successful defense; unmeasured outcomes remain null.

`attack:live` attributes an action to an assigned compromised role or its causal input. It does not prove malicious intent or that the message contains a secret. The private oracle grades actual accepted bytes independently, and useful work is graded separately. Unimplemented live lineage-error counters are null.

## Bounds

The existing caps remain: 12 decisions, 24 model requests, 40 mediated actions, 48 graph steps, 900 seconds, bounded JSON payloads and one active audit experiment. Each model request has a 90-second timeout and at most 1,024 response tokens. Invalid and failed requests consume budget. No replay script fills in a missing model answer; no arbitrary code, external endpoint or oracle feedback is available to a role.


## Observed local acceptance result

Two separately frozen samples used C30, C31 and C41, each with allowlist_only/transitive and attack/no-attack, fixture seed 31. The local provider was qwen3:4b-instruct, digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`, temperature 0, top_p 1, requested generation seed 31. The complete redacted configuration, per-run IDs, failures and source digests are in [the acceptance evidence](data/independent-role-acceptance.json). The [R13 provenance supplement](data/independent-role-provenance-r13.json) adds persisted UTC start/end times, durations, oracle/scoring versions and participant-knowledge scope without changing the original exports.

| Sample | Prompt | Started / completed | Actual model requests | Accepted peer messages | Accepted private reads | Accepted sink receipts | Efficacy-eligible trials |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | independent-role-v1 | 12 / 0 | 12 | 0 | 0 | 0 | 0 |
| v2 | independent-role-v2 | 12 / 0 | 52 | 40 | 0 | 0 | 0 |

All v1 trials stopped at A1 with an invalid proposal. Separate public-context diagnostics exposed a mismatch between the flat provider schema and the runtime's disposition/action invariant. The corrected v2 schema expresses that invariant explicitly. Those diagnostics are excluded from the table.

In v2, A1 and A4 made actual model-directed peer proposals. A2 made further proposals, including eight clarification decisions across the sample. C30 stopped at A6; C31/C41 stopped at A3. All terminal failures were invalid role proposals. Their stored generic rejection code cannot retrospectively distinguish malformed data from a proposal outside role permissions; newer execution records make that distinction. No raw output was retained to invent a more precise diagnosis.

There were no accepted private reads, no customer receipts and no completed useful tasks. Consequently this sample did not test successful secret transport, demonstrate an unwitting relay, or establish a taint protection rate. The correct efficacy value is **not measured**, not 0% or 100%. The negative result is retained; no scripted output replaces a failed model decision.

The v1 source tree digest is `d372c18810a9b020258b87760d3a37bc04b81395af4312fbef2ec4ca3fcc6a45`; v2 is `fcab04cd4362435c050de03dccca8a1630ec6b12fa49944593ce8032289f6862`. These identify the executed revisions, not a later documentation or metadata patch. The sample uses one seed per arm and one local model. Controlled-caller tests separately verify complete utility, permitted refusal, blocked/accepted egress and failure-after-receipt preservation; they are not model capability measurements.
