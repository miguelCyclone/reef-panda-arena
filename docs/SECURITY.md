# Security scope and design

## Scope

Reef Panda Covert Channel Arena is a **local synthetic-data research environment**, not an endpoint for real confidential information. All tool adapters are simulations and outbound delivery is stored locally. No user-generated executable code, arbitrary HTTP requests or real SMTP is permitted in agent tools.

The attacker controls the output of one selected worker (and its permitted tool arguments), but **not** source code, operating system, database passwords, trusted oracle, declassification rules, gateway implementation, or other workers' private state. This is a strong boundary for an application-layer exercise but not a proof against full endpoint compromise.

## The core risk

A normal-looking but authorized tool call can leak information in content, structure or action selection. Valid schema does not imply permitted information flow. Tools must accept **only** explicitly validated fields and a bound security context. Gateway checks happen after generation and before side effects.

## Recommended threat controls

- Source-label sensitive values at trusted tool results, keep recipient scope and allowed purposes.
- Enforce least privilege for read vs write vs egress **separately**.
- Use an allowlisted mock tool registry; deny unknown tool names and unrecognized fields.
- Validate each tool call with a Pydantic schema and per-run rate and byte caps.
- `actor_id` and `run_id` come from trusted graph runtime, never from LLM arguments.
- No outbound HTTP; mock sink is an implementation-internal API with no configurable external URL.
- A “reviewed” or “approved” text string is data, not authority. Approval decisions are explicit records bound to exact arguments.
- Keep oracle and expected secret out of agent-visible prompts and graph shared state.
- Log policy reasons, SHA-256 digests, classifications and safe summaries, not plaintext secrets.
- Secret vault ciphertext is encrypted with locally supplied AES-GCM key (not checked in). This provides protection against casual DB inspection, **not** against a compromised app process.
- No arbitrary code execution even if a model asks for it.
- Do not silently downgrade policy on model/tool errors; report failed run.

## Limits of detection

Simple decoding and regex do not detect all steganography. Content filtering cannot provide general covert-channel guarantees. Provenance/taint helps when every source and transformation is mediated, but it can be conservative, create false positives and be bypassed if unmodeled channels exist. Therefore benchmark both confidentiality and legitimate task utility.

## Event push policy

SSE pushes new events; the browser has no database polling loop. Heartbeats occur at 30 seconds. After a disconnect, the browser closes its EventSource, fetches persisted history, and retries only after 30 seconds. It stops after 300 seconds without user interaction and reconnects again only on explicit user action. Server subscriptions are released on disconnect and close after 300 seconds. There is no background MySQL scan loop.

## Vulnerability reporting

See root [SECURITY.md](../SECURITY.md). Never submit actual passwords or sensitive customer data as part of an issue. Reproduction cases use test-generated fixtures and mock sinks exclusively.
