# Fixture modes and participant knowledge

New runs declare a fixture mode and a versioned access contract. These fields
explain which information a component can receive. Boundary events establish
whether a particular read or inspection actually occurred. A declaration alone
is not evidence of a successful read, detection, release or leak.

## Running either mode

The default is `key_derived_unknown`. The trusted harness derives protected
values from the private local key and the public scenario/seed. The public
fixture files and seed alone do not determine those values.

For a reproducible public transport control, set the mode when starting the
CLI or server:

```bash
ARENA_FIXTURE_MODE=public_transport_control .venv/bin/reef-panda-arena run C12 --defense none --seed 31
ARENA_FIXTURE_MODE=public_transport_control .venv/bin/reef-panda-arena serve --port 8000
```

Omit the environment override to use the configured default. A mode explicitly
set in the private `.env` also applies. The model and run-request API cannot
supply a fixture key. Public controls exercise source labels, transport,
policies and receivers, but do not establish unknown-secret efficacy.

C10–C14 public controls retain the original finite JSON values. Other families
use a fixed, intentionally public synthetic control key declared in source
code. Private vault storage still uses the private local encryption key in
both modes. Random authenticated-encryption nonces remain fresh, so repeated
runs can share a target without producing identical ciphertext.

## What “unknown” means

Unknown is relative to a participant's permitted view. An attacker can learn
values through an accepted classified source read. An observer can encounter a
marker in an actual proposed literal disclosure. A privileged content policy
can receive the expected marker from the harness. These facts do not change the
fixture mode; they describe different knowledge boundaries.

The fixtures have small finite domains. Key derivation does not create 256 bits
of target uncertainty. Some targets have only two possible values or sixteen
possible values. Different private keys can therefore produce the same target.
The larger markers are fixed base36 strings, and modulo-based generation does
not promise perfectly uniform sampling. No derivation searches for favorable
values to make an attack or utility test pass.

C11 derives both its marker and its confidential exact fee. Its scripted fee
disclosure remains a separate component result, not full marker recovery.
C17/C19/C20 literal marker representations spell the same underlying numeric
value used by their specialized receiver. They are not independent secrets.

## Policy, observer and receiver access

| Component or profile | Declared access |
| --- | --- |
| `none`, `allowlist`, `allowlist_only` policy | No content inspection; mandatory runtime identity/schema rules still apply. |
| Legacy `content`, `combined`, `declassify_strict` policy | Privileged expected-marker matching. For C11, this marker is not the fee. Other enabled checks remain profile-specific. |
| Unified `content_only` policy | Learns the account code only from a committed `private.account` read. |
| Taint/provenance policy | Runtime source/dependency labels; a taint block does not verify that output bytes encode the secret. |
| Content observer | Keyless proposed-content view, with its recorded traversal limits. |
| Metadata/math observer | Keyless proposal/metadata view and bounded prior proposal history. |
| Provenance observer | Keyless proposal view plus runtime labels. |
| Receiver/oracle | Accepted sink bytes, the expected target for comparison, and any case-specific receiver inputs below. |

The observer and policy are separate components. A keyless observer does not
make a combined experiment keyless when its policy receives a privileged
expected marker. Observer alerts also remain separate from policy blocks.
Core C00–C09 runs currently have no independent observer; their knowledge field
records `disabled`.

Decoding conventions are public source code. C06 and C17 use public finite
codebooks; C12 and C13 independently invert accepted choice/coefficient bytes.
C20's specialized receiver additionally selects the issued attack identifier.
C14/C21/C24 require an issued artifact and authenticate/decrypt it with a
receiver key before comparing its plaintext target. Their algorithm is public;
the receiver key is private in unknown mode and publicly derivable in control
mode. The displayed curve point does not turn this into an elliptic-curve
encoding or a new cryptographic construction.

## Adaptive proposer custody

The adaptive harness retains the private case for deterministic interpretation
and post-run scoring. The proposer receives a separate immutable source view.
Its construction checks an accepted read against published registry evidence:
run, reader, source tool, field labels, source event and value bindings.

Denied reads, wrong readers, substituted data, incomplete evidence and unbound
execution do not supply a proposer input. The source view contains the accepted
source record and public task hint; it contains no receiver key, complete
private case or oracle feedback. A literal marker present in the authorized
source is legitimate attacker input.

The prompt version is `adaptive-model-v5`. This input restriction does not make
scripted intermediaries autonomous. Independent live role behavior remains a
separate experiment. All components execute inside trusted local Python; this
is an application access contract, not isolation from malicious host code.

A C28 frozen transfer must come from a completed development run with the same
fixture mode and recognized derivation/knowledge versions. Undeclared
historical or cross-mode transfers are rejected before target-run creation.

## Reports and historical rows

The CLI, API, CSV and dashboard carry the same nullable metadata:

- `fixture_mode`, `fixture_derivation_version`, `fixture_template_digest`;
- `knowledge_contract_version`, `protected_target_kind`, `attacker_knowledge`;
- `policy_knowledge`, `policy_known_target`, `observer_knowledge`;
- `receiver_knowledge`, `receiver_target_comparison`, `decoder_convention_public`.

These declarations are persisted at run creation, so failures retain them.
Historical absent metadata remains unknown. It is never inferred from the
current default, seed, policy or latest implementation.

The template digest hashes public input only: raw JSON for the finite
registries, canonical public shipping JSON for core/unified runs. It is not a
protected-target commitment. New unified runs leave the legacy `fixture_hash`
field null. Historical keyed HMAC values may remain available for compatibility;
they must not be presented as proof of secret custody. Public event/sink
projections omit payload hashes. Restricted SQL digest columns still exist and
are outside the ordinary public report surface.

Benchmark consumers keep public controls, private trials and undeclared
historical evidence in separate mode/version groups. A missing or failed report
does not inherit requested settings as measured knowledge. Completed recovery,
receipt evidence, observer coverage and useful task completion keep their own
eligibility rules.

Published measurement tables from earlier source revisions remain historical.
A new generator, input contract or passing test does not itself provide a new
efficacy measurement.
