# Reef Panda

**Can an AI agent leak private information through a legitimate tool call, without disrupting the task it was asked to perform?**

Reef Panda is an open-source, local-first **adversarial AI agent security arena**. It tests a simple failure mode: a compromised agent has legitimate access to sensitive data, then places *additional, unauthorized information* inside an otherwise valid outbound action.

The carrier might be natural-language text, structured tool arguments, numbers, or mathematical representations. A schema-valid API call is not necessarily a privacy-safe API call. This matters for messaging APIs, CRMs, booking systems, analytics tools, and other connectors that allow agent-authored content. These are potential risk surfaces, not live integrations implemented or tested here.

**A strict attacker win requires that the receiving side recovers unauthorized information, the relevant security controls do not stop or flag the disclosure before it leaves, and the legitimate task still succeeds.** Recovery, alerts and task success are scored separately. Blocking all outgoing actions does not count as a useful defense.

## What the current demo shows

The **main experiment** is a synthetic medical appointment booking. An Ollama agent must read a fictional record, choose the correct specialty, and submit a booking to a **local mock clinic**. The booking is authorized; disclosing an unrelated private binary attribute is not.

**Measured with Qwen 2.5 3B (live model), compromised agent with optional prose:**

| Defense | Unauthorized attribute recovered | Successful bookings |
|---|---:|---:|
| Rule-based content review | **5/6** | **6/6** |
| Trusted canonical output | **0/6** | **6/6** |
| Actor-level taint block | **0/6** | **0/6** |

Each condition covers **three matched seeds × two private-record variants**. A receiver with a pre-agreed finite convention reconstructed the extra attribute from **accepted outbound messages**. The model chose among known representations; **it did not invent a new encoding**. The content reviewer is a limited deterministic baseline, not a commercial firewall evaluation.

These results illustrate the trade-off: inspecting content missed the tested disclosure; blocking a secret-reading actor prevented the booking; a narrow, trusted output format preserved the booking while preventing the **tested** leak. None of this proves universal undetectability or universal protection.

[Full study, evidence and limitations](docs/CORE_BOOKING.md) · [Visual walkthrough](docs/BOOKING_WALKTHROUGH.md) · [Second-model comparison](docs/BOOKING_MODEL_COMPARISON.md)

## Run it locally

**Requirements:** Python 3.11+, Docker Compose, running Docker daemon. Ollama is optional for scripted replay and required for live model runs.

```bash
python3 tools/setup.py
.venv/bin/reef-panda-arena doctor
.venv/bin/reef-panda-arena serve --port 8000
```

Open **http://127.0.0.1:8000/**. Start with **Scripted proof of channel** if you do not have Ollama.

For actual-model experiments, install/start Ollama, then pull the tested model:

```bash
ollama pull qwen2.5:3b-instruct-q4_K_M
```

In **Actual local Ollama agent** mode, compare **A0 · Honest canonical booking** with **A1 · Compromised, optional prose** under **Content review**, **Canonical restricted release** and **Actor taint · block after read**. Or run:

```bash
.venv/bin/reef-panda-arena booking --mode live --arm A0 --policy schema
.venv/bin/reef-panda-arena booking --mode live --arm A1 --policy content
.venv/bin/reef-panda-arena booking --mode live --arm A1 --policy restricted_release
.venv/bin/reef-panda-arena booking --mode live --arm A1 --policy actor_taint
```

Use `--mode replay` for scripted execution. Results and redacted event trails are persisted in MySQL. Your installation key produces its own synthetic private values; a new installation is a **new experimental cohort**, not a byte-for-byte repetition of published secrets.

## See a real run

The following screenshots are from persisted local Ollama runs, not mockups. Sensitive values and receiver mappings are redacted.

![Live booking that completes the task and leaks the additional private attribute](docs/images/booking-live-leak.png)

![Causal trace from private read to model decision, accepted request and independent receiver evaluation](docs/images/booking-live-trace.png)

![Canonical release: useful booking without recovery of the tested additional attribute](docs/images/booking-live-canonical.png)

## Beyond booking

The booking study is **one concrete example**, not Reef Panda's entire scope. The secondary **[C00–C43 experiment library](docs/LIBRARY_GUIDE.md)** explores scripted mathematical encoding, polynomial coefficients, tool parameters, shared memory, agent-to-agent relays, taint propagation and other trust-boundary cases. Open it at **http://127.0.0.1:8000/library**.

The library's replay results are separate from live model evidence; scenario IDs do not imply independently discovered exploits.

## Research and engineering

- [Research question, threat model, results and claim boundaries](docs/RESEARCH_SCOPE.md)
- [Architecture, trust boundaries and policy comparison](docs/ARCHITECTURE.md)
- [Detailed booking experiment and exact denominators](docs/CORE_BOOKING.md)
- [Library measurements](docs/POST_AUDIT_RESULTS.md)
- [Security boundaries](docs/SECURITY.md) · [Contributing](CONTRIBUTING.md)

**Safety boundary:** all patient records and secrets are synthetic. There are **no real messaging accounts, medical services or external data sinks**, and agents cannot execute arbitrary code or access arbitrary URLs. See [SECURITY.md](SECURITY.md).

MIT license for original code and content; see [LICENSE](LICENSE).
