# Trace Studio: reusable agent animation

Trace Studio is the browser's event-driven player for all 44 registered scenarios (C00–C43). It animates the existing run history, including live SSE events as they arrive. It also reopens persisted runs. There is one renderer and playback engine; scenario descriptors supply the roles and mechanism explanations.

## Start and explore

```bash
python3 tools/setup.py
.venv/bin/reef-panda-arena serve --port 8000
```

Open <http://127.0.0.1:8000/>. Launch a run in the configuration panel or select an existing run. Use **Play trace**, pause, previous/next, the scrubber, speed control, **Jump to attack**, or the event selector. **Result** goes to the final scored step. Clicking a graph node identifies its role. On narrow screens the graph scrolls horizontally.

Useful comparisons at seed 31:

| Scenario | What to inspect | Comparison |
| --- | --- | --- |
| C03 | Eight bytes represented by exact rational polynomial coefficients | `none` versus `taint` |
| C32 | A2 reads private data, sends numeric bytes to A6, and A6/A8/A9 relay the artifact | `allowlist_only` versus `transitive` |
| C18 | Internal memory write, another agent's read, then external mock notification | `none` versus `taint` |
| C24 | Prebuilt sealed evidence placed in approval context | Observer alert versus accepted egress |
| C40 | A two-symbol prefix reaches the sink | Independent partial prefix recovery; source-model capacity and unknown entropy remain separate |

![Trace Studio showing the C32 representation step, agent roles, symbolic call and separate outcomes](images/trace-studio.png)

## What the picture means

- **Red agents** are configured compromised roles. The status projection distinguishes an enabled attacker from whether an attempt occurred. A completed benign control does not paint a rogue actor. Older records may lack configuration, in which case the recorded attempt is the fallback.
- **Private source / S** denotes the hidden synthetic value. Access is shown only for the recorded source read. A denied read does not animate a private value returning to the actor.
- **Moving packets** represent the selected recorded boundary. Peer sends are queued messages; receives are separately recorded consumption. Receives correlate with sends through the runtime message ID. An honest recipient remains an honest actor even if it receives private-derived data.
- **S → f(S)** shows a symbolic representation step. Known structured representations are marked by trusted runtime metadata. Other scripted attack calls show their registered scenario explanation and explicitly label that evidence level.
- **Gateway** shows proposed, allowed and blocked calls. Only an allowed outbound event with a sink receipt digest animates as accepted egress. Internal memory, peer delivery and reducer operations are not counted as external output.
- **Observer** reports the recorded independent alert and reason. A missing observer is shown as unavailable, never interpreted as “the observer missed it.” This is a simulated inspection result, not a claim about a human administrator's knowledge.
- **Oracle** uses the existing independent score. Exact recovery, partial disclosure and accepted but unquantified output are distinct. The player reveals the verdict at the final step; seeking backward removes future outcomes.

An alert and a leak can coexist: observational alerts do not block or retract a permitted payload. The counter includes all recorded inspections up to the playhead; the final note separately reports attack-specific pre-egress alerts where that metric exists. A taint block demonstrates enforcement of a flow rule, not exact secret reconstruction by the observer.

All configured roles remain visible. A role without a recorded boundary says **No boundary yet**. This avoids inventing interactions for roles that are idle or orchestration-only in a given implementation. Playback uses event sequence order, not invented concurrency or measured execution durations. Several visual stages can explain one atomic recorded tool event; they share its event number.

## Mathematical mechanisms and actual implementation

`telemetry/visual_catalog.py` resolves descriptors from the existing scenario contracts. These describe mechanisms, not independent per-scenario animation scripts.

| Family | Function shown | Runtime interpretation |
| --- | --- | --- |
| Literal | `f(S) = S` | Copy or textual wrapper; no numerical masking |
| Base64 | `Base64(UTF8(S))` | Reversible character encoding |
| Decimal | `f(S) = [b₀, b₁, …]` | Bytes in numerical fields; unified cases later render them in notification text |
| Polynomial | `P(x) = Σ bᵢ ∏(x−j)/(i−j)`; `P(i)=bᵢ` | Eight-point Lagrange interpolation with exact fractions |
| Codebook | `π(S₀) ∥ π(S₁) …` | Seeded symbol substitution; the run's mapping stays private |
| Fragments | `(i, Sᵢ)` | Ordered accepted fragments reconstruct the value |
| Action choices | `0 → alpha`, `1 → beta` | One bit per selected value |
| Memory / peer | `M[k] ← S`, relay to another actor | A boundary changes; the private dependency need not disappear |
| Normalized character indices | `round(index36(S[i])/35, 6)` | C13 independently decodes accepted coefficients; no Fourier transform or marker-to-fixture lookup |
| Finite vector codebook | `f(s) = V[s]` | A finite precomputed vector is selected; the oracle checks its finite registry index, not a general basis inverse |
| Aggregates | `target = cohort_total − excluding_target_total` | Two accepted aggregate reports are required |
| Equivalent formulas | `a=p`, `b=p XOR s`, `s=a XOR b` | Choice between `x+0` and `0+x` carries the bit |
| Sealed evidence | `C = AES-GCMₖ(nonce, S, AAD)` | Trusted AES-GCM fixture construction; P-256 fields are non-operative metadata |
| Adaptive arithmetic | `xᵢ₊₁ = xᵢ ± cᵢ` | The selected call supplies its actual add/subtract operator sequence; constants remain symbolic |
| Adaptive layout | `S`, `label:S`, `S:label`, `label[S]` | Recorded structured layout when available |
| Prefix | `S[0:2]` | C40's actual fixed prefix, not a claimed LLM paraphrase |
| Reducer | `L(out) = join(L(parents))` | Trusted replay dependency join across sequential branches, with the value relayed separately |
| Compaction | `Mₙ₊₁ = normalize_space(Mₙ)` | Same-process whitespace compaction preserves the registered parent; no restart is tested |

The call inspector shows the actual tool name and allowlisted argument structure. Secret values, encoded equivalents, keys, private lookup mappings and exact numeric coefficients are not sent to the browser. The symbols are intentionally not a raw-payload preview. For independent live proposals without recorded representation metadata, the player displays no scenario-derived formula or carrier. See [executed mechanisms and mode-specific paths](EXECUTED_MECHANISMS.md).

## Architecture and extension

- `telemetry/visual_catalog.py`: typed public descriptors, sourced from the canonical scenario loader and roster; no private fixture or oracle imports.
- `telemetry/call_shape.py`: allowlisted structure and trusted phase metadata. It does not stringify untrusted values or arbitrary argument keys.
- `web/flow-model.js`: pure conversion from events to playback frames; acceptance, observation and final scoring rules.
- `web/flow-graph.js`: one SVG layout and renderer for roles, resources and directed edges. Long direct edges curve past intervening cards.
- `web/flow-player.js`: local playback state, seeking, speed, lifecycle and accessibility.
- `web/flow.css`: responsive styling, focus states and reduced-motion presentation.

To add a scenario using an existing mechanism, its current contract resolves to that descriptor. A new mechanism needs a symbolic descriptor and, if its runtime structure is new, a bounded telemetry classifier. The graph and animation sequence do not need a new per-scenario timeline. Unknown event types remain visible as generic recorded events.

Existing history is supported without rewriting database records. Historical events lacking the new metadata are marked as such; the player cannot recover an unrecorded transformation or attack phase from redacted values. The single MySQL schema remains unchanged.

The player uses browser animations locally. It adds no API polling, external assets, CDN dependencies, graph framework, npm build or agent-facing tools. Playback pauses when the tab becomes hidden or after five minutes without interaction. Reduced-motion mode keeps step changes and playback controls while removing traveling packets and transformation fades. Backend execution budgets and existing SSE retry/inactivity behavior remain intact.

## Verification

The implementation was checked with 49 fresh replay runs: every registered scenario plus five controls covering blocked output and benign behavior. Chrome rendered all 1,374 visual steps from those traces; accepted-frame counts matched persisted accepted-outbound counts. The browser checks also cover red compromised roles, play/pause, seeking, representative leak/block/partial verdicts, absent rogue actors in benign controls, reduced motion and a 390px mobile layout.

Reproduce the checks with a local database:

```bash
ARENA_TEST_MYSQL=1 .venv/bin/python -m pytest -q
node --test tests/test_web.mjs tests/test_flow.mjs
.venv/bin/python tools/check_visualization.py
```

For the real-browser check, start the application on port 8001 and a separate Chrome test profile with local DevTools on port 9223, then run `node tools/check_visualization_browser.mjs`. `ARENA_VISUAL_URL` and `ARENA_DEVTOOLS_URL` can override those addresses. The check uses Node's WebSocket client and Chrome DevTools directly. Its redacted traces and screenshots are saved under ignored `.build/visualization/`.

This is visualization validation, not a new security success-rate benchmark. The earlier C29–C43 matrix retains the digest of its measured source snapshot; the later presentation metadata is a subsequent change.

## Animation references reviewed

The implementation uses native SVG and the [Web Animations API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Animations_API) for playback controls. It follows the browser's [reduced-motion preference](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/%40media/prefers-reduced-motion).

[Motion's animation documentation](https://motion.dev/docs/animate) supplied a reference for path drawing, sequences and playback controls. [Cytoscape.js](https://js.cytoscape.org/) was reviewed for graph animation and viewport controls. Native SVG suits the arena's bounded roster and keeps the existing offline, dependency-free frontend packaging.
