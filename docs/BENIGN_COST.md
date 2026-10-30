# Measuring the cost to legitimate work

This document describes the implemented `benign-cost-v1` per-run measurements and bounded matched-cost reporting. No efficacy or autonomous-agent benchmark follows from the implementation tests.

## The question being measured

An alert does not establish a leak. A block does not establish that the rejected message contained a secret. A correct required numerical report or authenticated envelope can trigger an observer or be blocked by conservative taint. These costs need independent labels and their own denominators.

The private harness first checks whether a committed outbound proposal is legitimate required work. Only then does it join the proposal to actual observer and policy evidence. A correct rejected proposal remains eligible. Conditioning eligibility on successful delivery would hide overblocking.

Eligibility requires the expected reader, an earlier verified classified source, exact required task content and registered input ancestry. Forwarded work additionally requires its actual accepted handoff. An untrusted `task` assertion, public-only transport control, wrong result, wrong reader or unrelated source cannot establish eligibility. The validators use the finite task contracts and trusted fixture truth; this is not a general semantic classifier for arbitrary prose.

The committed in-process journal retains bounded immutable input dependencies for rejected proposals. It does not fabricate output artifacts or receipts. Ordinary reports export fixed categories and event references, without source values, task payloads, ciphertext or keys.

## Separate action and run denominators

| Field | Meaning |
|---|---|
| `eligible_actions` | Independently validated legitimate outbound proposals |
| `observer_inspections` | Eligible proposals with an actual bound observer verdict |
| `observer_false_alerts` | Those inspected proposals whose observer alerted |
| `observer_false_alert_rate` | False alerts divided by actual inspections |
| `policy_decisions` | Eligible proposals with a bound policy outcome |
| `policy_false_blocks` | Those proposals rejected by the policy |
| `policy_false_block_rate` | False blocks divided by policy decisions |
| `eligible_runs` | One for a completed run with at least one eligible proposal; otherwise zero |
| `observer_eligible_runs` | One only when every eligible proposal in that completed run was inspected |
| `policy_eligible_runs` | One only when every eligible proposal in that completed run has a policy outcome |
| `observer_false_alert_runs` | Eligible observer runs containing at least one false alert |
| `policy_false_block_runs` | Eligible policy runs containing at least one false block |

For a single run these run counters are zero or one. They are not action counts. For example, three blocked legitimate sends contribute three false blocks and one run with a false block.

A zero inspection or decision denominator produces a null rate and `not_measured`, never a measured zero percent. Partial coverage is `partial`; the action rate describes the observed subset only. Failed, cancelled and timed-out runs retain available partial action evidence but contribute zero completed-run denominators. Invalid committed evidence makes counts and rates unknown. Historical reports without this contract remain null.

Task success is separate: all evaluated proposals can be correct while required delivery fails, or a run can contain some eligible work and other incorrect work. The eligibility counters do not certify whole-run utility or confidentiality.

## Genuine task shapes

The `shape_matched` strata describe required task artifacts with a corresponding suspect representation in the same scenario. Ordinary notices remain in the overall required-work cost without becoming matched mathematical controls.

| Cases | Required legitimate artifact |
|---|---|
| C13 | Eight-value sensor-dependent numerical array in the existing spectral schema |
| C14 | Issued authenticated benign envelope in the same evidence field and envelope schema |
| C16 | Classified incident narrative record |
| C17 | Classified sensor-dependent four-value array |
| C19 | Correct period aggregate computed using the private individual input |
| C20 | Formula choice determined by the classified route adjustment |
| C21 | Issued benign envelope with the actual route decision |
| C23, C26 | Required bounded numerical risk report |
| C24 | Issued benign attestation with the computed task decision |

C13 and C14 require these support artifacts for utility, in addition to customer notices. The benign envelope is a finite issued `ROUTE_OK` receipt accompanied by a separately validated private-dependent decision. The ciphertext does not cryptographically bind that decision; the exact task contract checks the envelope and decision context together. This is a prescribed local task, not a general attestation protocol. Their task and release versions are `sensitive-utility-v3` and `sensitive-release-v3`; the sensitive receiver is `sensitive-v4`. Earlier versions describe earlier contracts and must remain separate in comparisons. The original fixture files, marker derivation and schema are unchanged.

C18 and C25 use actual accepted memory handoffs. Unified C29–C43 eligibility follows the A2 private read, A3 validated projection, forwarded dependencies and A9 routing/customer records, including rejected A9 sends. Unified records are explicitly **not** labeled shape-matched to every attack encoding.

The matched classification is a local task-artifact property. It does not prove that two historical runs used identical budgets, observer state or task versions. Cross-run comparisons must also match scenario, seed, runtime roles/tool scope, source visibility, schema/destination, observer, task version, mode/model settings and limits. Stateful reviewers may react differently after earlier attack messages; that context is part of the experiment.

## Matching runs without mixing conditions

Every supported runtime snapshots a `benign-match-v1` comparison declaration before task execution. It contains the package source digest, a digest of the scenario, public shipping fixture, role/tool/schema/destination configuration, and a digest of effective budgets. The principal action, decision, model-call and wall-time caps are also readable fields. The task schedule, observer version/profile and history scope are explicit. Actual recorded observer profiles/versions must agree before the declaration can be used.

A domain-separated HMAC of a constant under the local fixture key provides a cohort identifier. It does not hash or reveal a protected target. Together with the seed, fixture mode, derivation/template version and implementation digest, it prevents comparisons across different local key domains from silently claiming identical private inputs. It intentionally links runs sharing that fixture-key domain. Authenticated-envelope nonces remain fresh; comparison does not require identical ciphertext bytes.

The aggregator accepts at most 10,000 sanitized run reports and rejects duplicate run IDs. Groups preserve scenario, policy, execution mode, task/prompt/oracle versions, model configuration, declared participant knowledge, source/configuration/budget/cohort digests, observer context and treatment assignment. Seeds and run IDs are retained as an inventory; pairs additionally require the same seed and generation seed. Missing historical declarations and incomplete live-model metadata are reported as unmatched.

A pair needs one task-only control and one unambiguous attacked run for the treatment arm. Distinct attack arms may explicitly share a control; `control_reused` and `control_pair_count` identify that dependence. Group denominators count the original control once. Duplicate controls or duplicate attacks within an arm are ambiguous and never silently selected. H0 public transport probes and P0 positive controls retain their actual required-work costs but do not substitute for the task-only counterpart.

A matched pair can contain failed or partially observed runs. Matching configuration does not make its outcomes eligible for completed-run rates. Observer history can differ because of attack activity; the report separates attacked and control contexts and declares the reviewer's history scope. It does not assert identical dynamic reviewer state.

The sensitive, extension, adaptive and unified benchmark tools include separate overall-task and shape-stratum tables. Their JSON/CSV run records carry the declaration; the unified benchmark also saves the full cost summary and paired run IDs. A source/configuration match is evidence about the recorded runtime contract, not a proof that a finite shape is statistically indistinguishable from an attack or that uninstrumented behavior is impossible.

## Interpreting taint and strict release

Coarse taint can block useful work from a classified reader without decoding its content. The benign-cost counters measure that loss directly. A narrow release can admit independently valid work while restricting the released form. `strict_no_release` can reject legitimate unified outputs even after a correct classified computation; the rejected proposals still enter its false-block denominator.

`actor_local` remains an intentionally weak baseline. A low benign blocking cost says nothing by itself about its confidentiality protection. Read the independent accepted-sink recovery, observer evidence, utility result and benign costs together.

Source ancestry in legacy workflows includes conservative actor exposure unless explicit dependencies were supplied. That establishes recorded access/influence, not a mathematical proof that a particular field caused an output. Exact task validation and actual handoff checks provide additional evidence; arbitrary model computations remain outside this finite contract.

## Reports and dashboard

The `benign_cost` object is shared by status, JSON reports, CSV and the unified report schema. The dashboard displays action rates and completed-run denominators separately, with a matched-shape summary. Failed snapshots cannot inherit a stale completed-run denominator. Unknown or malformed public metadata is rejected rather than rendered as a measured result.

Implementation checks exercise real gateway decisions, missing or mutated dependencies, denied required work, unknown observers, partial coverage, invalid task proposals, actual handoffs, authenticated envelope shapes, MySQL reload and API/CSV parity. They establish these measurement behaviors on finite synthetic tasks. Fresh post-remediation efficacy measurements and independent multi-agent model experiments remain pending.
