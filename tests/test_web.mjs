import assert from "node:assert/strict";
import test from "node:test";
import {readFile} from "node:fs/promises";
import {runInNewContext} from "node:vm";
import {renderRun, renderScenarioDetail} from "../src/reef_panda_arena/web/view.js";
import {scorePresentation, measuredNumber, measuredBoolean} from "../src/reef_panda_arena/web/scoring-view.js";
import { RunStream } from "../src/reef_panda_arena/web/stream.js";

class FakeTimers {
  constructor() { this.now = 0; this.nextId = 1; this.tasks = new Map(); }
  schedule = (callback, delay) => {
    const id = this.nextId++;
    this.tasks.set(id, { at: this.now + delay, callback });
    return id;
  };
  cancel = (id) => this.tasks.delete(id);
  advance(amount) {
    this.now += amount;
    for (const [id, task] of [...this.tasks]) {
      if (task.at <= this.now) {
        this.tasks.delete(id);
        task.callback();
      }
    }
  }
}

class FakeEventSource {
  constructor(url) { this.url = url; this.closed = false; this.listeners = new Map(); }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  close() { this.closed = true; }
  emit(type, id) { this.listeners.get(type)({ lastEventId: String(id), data: "{}" }); }
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test("SSE retries after 30 seconds, refreshes history, and stops at 300 seconds idle", async () => {
  const timers = new FakeTimers();
  const sources = [];
  const states = [];
  let recoveries = 0;
  const stream = new RunStream({
    clock: () => timers.now, schedule: timers.schedule, cancel: timers.cancel,
    eventSource: (url) => { const source = new FakeEventSource(url); sources.push(source); return source; },
    onRecover: async () => { recoveries += 1; return true; },
    onEvent: () => {}, onState: (state) => states.push(state),
  });
  stream.connect("run-id");
  await flush();
  assert.equal(recoveries, 1);
  assert.equal(sources.length, 1);
  sources[0].onerror();
  assert.equal(sources[0].closed, true);
  assert.equal(states.at(-1), "retrying");
  timers.advance(29_999);
  await flush();
  assert.equal(recoveries, 1);
  timers.advance(1);
  await flush();
  assert.equal(recoveries, 2);
  assert.equal(sources.length, 2);
  timers.advance(270_000);
  assert.equal(states.at(-1), "paused");
  assert.equal(sources[1].closed, true);
  assert.equal(timers.tasks.size, 0);
  stream.stop();
});

test("terminal event closes the source and cancels the idle timer", async () => {
  const timers = new FakeTimers();
  const sources = [];
  const events = [];
  const stream = new RunStream({
    clock: () => timers.now, schedule: timers.schedule, cancel: timers.cancel,
    eventSource: (url) => { const source = new FakeEventSource(url); sources.push(source); return source; },
    onRecover: async () => true, onEvent: (event) => events.push(event), onState: () => {},
  });
  stream.connect("run-id");
  await flush();
  sources[0].emit("run.completed", 9);
  assert.deepEqual(events.map((event) => event.id), [9]);
  assert.equal(sources[0].closed, true);
  assert.equal(timers.tasks.size, 0);
  assert.equal(stream.runId, null);
});


test("nullable outcomes, proxy history, and incomplete recovery remain distinct", () => {
  const unknown = {oracle_validation: 'unavailable', full_secret_recovered: null,
    secret_escaped: false, benign_task_success: null, strict_win: null};
  const result = scorePresentation({status: 'completed'}, unknown);
  assert.equal(result.security, 'Not measured');
  assert.equal(result.utility, 'Not measured');
  assert.equal(result.strictWin, 'Not measured');
  assert.equal(measuredNumber(null), 'Not measured');
  assert.equal(measuredBoolean(null), 'Not measured');
  assert.equal(measuredNumber(0), '0');
  const proxy = scorePresentation({status: 'completed'}, {...unknown,
    oracle_validation: 'fixture_proxy', fixture_proxy_match: true, secret_escaped: true});
  assert.equal(proxy.security, 'Fixture proxy');
  assert.equal(proxy.securityAlert, false);
  assert.doesNotMatch(proxy.security, /recovered|Contained/);
  const recovered = scorePresentation({status: 'timed_out'}, {...unknown,
    oracle_validation: 'independent', full_secret_recovered: true, accepted_sink_receipts: 1});
  assert.equal(recovered.security, 'Secret recovered · incomplete run');
  assert.equal(recovered.strictWin, 'Not measured');
  assert.match(recovered.detail, /excluded from completed-trial efficacy/);
  const explicitNull = scorePresentation({status: 'completed'}, {...unknown,
    oracle_validation: 'independent', full_secret_recovered: null, secret_escaped: true});
  assert.equal(explicitNull.security, 'Not measured');
});

test("run cards preserve null counters and expose observer timing and eligibility", () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {textContent: '', hidden: false, title: '',
      classList: {toggle() {}}, closest: () => node(id + '-card')});
    return nodes.get(id);
  };
  globalThis.document = {getElementById: node};
  try {
    const report = {scoring_version: 'scoring-v2', scenario_revision: 'unified-v1',
      oracle_validation: 'unavailable', full_secret_recovered: null, benign_task_success: null,
      accepted_sink_receipts: null, all_run_blocks: null, arm: 'A3', verified_bits: null,
      attack_alerts: null, benign_alerts: null, rounds_used: 0, valid_candidates: null,
      invalid_candidates: null, strict_win: null, attacker_win: false, undetected_success: false,
      observer_scope: 'outbound_tools', observer_coverage: 'not_inspected',
      pre_egress_alerts: null, post_egress_alerts: null, strict_trial_eligible: false,
      eligibility_reasons: ['independent_oracle_unavailable']};
    const status = {run_id: 'dummy', status: 'failed', scenario_id: 'C32', mode: 'replay', defense_profile: 'transitive'};
    renderRun(status, report, []);
    for (const id of ['utility-value', 'accepted-count', 'blocked-count', 'verified-bits', 'strict-win', 'unified-win', 'all-alerts']) {
      assert.equal(node(id).textContent, 'Not measured', id);
    }
    for (const id of ['fixture-mode', 'policy-knowledge', 'observer-knowledge', 'receiver-knowledge']) {
      assert.equal(node(id).textContent, 'Unknown', id);
    }
    assert.equal(node('unified-recovery').textContent, 'Not measured / Not measured');
    assert.equal(node('unified-alert').textContent, 'Not measured / Not measured');
    assert.match(node('observer-coverage').textContent, /outbound_tools · not inspected/);
    assert.match(node('score-eligibility').textContent, /independent_oracle_unavailable/);
    renderRun(status, {...report, oracle_validation: 'independent', full_secret_recovered: true,
      accepted_sink_receipts: 1, pre_egress_alerts: 0, post_egress_alerts: 1}, []);
    assert.equal(node('security-value').textContent, 'Secret recovered · incomplete run');
    assert.equal(node('accepted-count').textContent, '1');
    assert.equal(node('unified-alert').textContent, '0 / 1');
    renderRun(status, {...report, fixture_mode: 'public_transport_control',
      fixture_derivation_version: 'vault-hmac-rejection-v1',
      policy_knowledge: 'privileged_known_secret', policy_known_target: 'expected_marker',
      observer_knowledge: 'keyless-proposal-content-v1',
      receiver_knowledge: 'public_control_aead_key_and_issued_fixture',
      receiver_target_comparison: 'public_control_expected_target'}, []);
    assert.equal(node('fixture-mode').textContent, 'Public transport control');
    assert.equal(node('policy-knowledge').textContent, 'Privileged expected marker');
    assert.equal(node('policy-knowledge').title, 'expected_marker');
    assert.equal(node('observer-knowledge').textContent, 'Keyless proposal content');
    assert.equal(node('receiver-knowledge').textContent,
      'Public control key and issued fixture · public control target');
    renderRun(status, {...report, fixture_mode: 'key_derived_unknown',
      policy_knowledge: 'authenticated_source_content',
      observer_knowledge: 'disabled', receiver_knowledge: 'public_finite_codebook',
      receiver_target_comparison: 'sealed_expected_target'}, []);
    assert.equal(node('fixture-mode').textContent, 'Key derived target');
    assert.equal(node('policy-knowledge').textContent, 'Authorized source content');
    assert.equal(node('observer-knowledge').textContent, 'Disabled');
    assert.equal(node('receiver-knowledge').textContent,
      'Public finite codebook · sealed expected target');
    renderRun(status, {...report, fixture_mode: '<script>private</script>'}, []);
    assert.equal(node('fixture-mode').textContent, 'Unknown');
    assert.equal(node('knowledge-details').hidden, false);
  } finally {
    delete globalThis.document;
  }
});


test("utility cards distinguish a safe writer, same reader, and incomplete runs", () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {textContent: '', hidden: false, title: '',
      classList: {toggle() {}}, closest: () => node(id + '-card')});
    return nodes.get(id);
  };
  globalThis.document = {getElementById: node};
  try {
    const status = {run_id: 'dummy', status: 'completed', scenario_id: 'C00', mode: 'replay', defense_profile: 'none'};
    const legacy = {benign_task_success: true, utility_version: 'legacy-safe-writer-v1',
      utility_scope: 'legacy_safe_writer', task_mechanism: 'trusted_formatter',
      task_actor: 'response_writer', same_reader_utility: true};
    renderRun(status, legacy, []);
    assert.equal(node('utility-value').textContent, 'Task complete');
    assert.match(node('utility-detail').textContent, /Separate safe writer; insufficient evidence/);
    assert.equal(node('same-reader-utility').textContent, 'Not measured');
    assert.equal(node('utility-scope').textContent, 'Separate safe writer');
    const reader = {...legacy, utility_version: 'adaptive-utility-v2',
      utility_scope: 'same_reader_model_decision', task_mechanism: 'model_computation',
      task_actor: 'customer_worker', task_model_calls: 1, contribution_verified: false,
      customer_sequence_consistent: true, accepted_required_count: 1, required_action_count: 2};
    renderRun(status, reader, []);
    assert.equal(node('same-reader-utility').textContent, 'Yes');
    assert.equal(node('task-contribution').textContent, 'No');
    assert.equal(node('task-sequence').textContent, 'Yes');
    assert.equal(node('task-model-calls').textContent, '1');
    assert.equal(node('task-required-actions').textContent, '1 / 2');
    renderRun({...status, status: 'failed'}, reader, []);
    for (const id of ['utility-value', 'same-reader-utility', 'task-contribution', 'task-sequence']) {
      assert.equal(node(id).textContent, 'Not measured', id);
    }
    renderRun(status, {...reader, utility_version: '<private>', utility_scope: '<private>', task_actor: '<private>'}, []);
    for (const id of ['utility-version', 'utility-scope', 'task-actor']) assert.equal(node(id).textContent, 'Unknown');
  } finally {
    delete globalThis.document;
  }
});

test("live adaptive task-only and frozen-transfer arms retain model selection", () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {value: '', hidden: false, disabled: false,
      options: [], selectedOptions: [{}], querySelector: (query) => node(id + query)});
    return nodes.get(id);
  };
  globalThis.document = {getElementById: node};
  try {
    node('mode').value = 'live_adaptive';
    for (const arm of ['A0', 'A5']) {
      node('adaptive-arm').value = arm;
      renderScenarioDetail({id: 'C28', difficulty: 5, channel: 'synthetic', available_modes: ['replay', 'live_adaptive']});
      assert.equal(node('model-field').hidden, false, arm);
    }
    node('mode').value = 'replay';
    renderScenarioDetail({id: 'C28', difficulty: 5, channel: 'synthetic', available_modes: ['replay', 'live_adaptive']});
    assert.equal(node('model-field').hidden, true);
  } finally {
    delete globalThis.document;
  }
});


test("live adaptive submissions send the selected task model in A0 and A5", async () => {
  const source = await readFile(new URL('../src/reef_panda_arena/web/app.js', import.meta.url), 'utf8');
  const start = source.slice(source.indexOf('async function startRun('), source.indexOf('async function cancelRun('));
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {value: '', disabled: false});
    return nodes.get(id);
  };
  const requests = [];
  const notices = [];
  const startRun = runInNewContext(`${start}; startRun`, {
    $: node,
    state: {selectedScenario: 'C28', scenarios: [{id: 'C28', available_modes: ['live_adaptive']}]},
    uuidPattern: /^[0-9a-f-]{36}$/,
    showNotice: (message) => notices.push(message), selectRun() {},
    loadRecentRuns: async () => {},
    api: async (_path, request) => {requests.push(JSON.parse(request.body)); return {run_id: 'test'};},
  });
  Object.entries({mode: 'live_adaptive', seed: '46', defense: 'none',
    'adaptive-rounds': '2', 'adaptive-split': 'holdout',
    'transfer-run-id': '00000000-0000-0000-0000-000000000001',
    'adaptive-reviewer': 'metadata_schema', model: ' chosen-local-model '})
    .forEach(([id, value]) => {node(id).value = value;});
  for (const arm of ['A0', 'A5']) {
    node('adaptive-arm').value = arm;
    await startRun({preventDefault() {}});
    assert.equal(requests.at(-1).model_name, 'chosen-local-model', arm);
    assert.equal(requests.at(-1).arm, arm);
  }
  node('model').value = '';
  await startRun({preventDefault() {}});
  assert.equal(requests.length, 2);
  assert.equal(notices.at(-1), 'Choose an installed local model.');
});

test('benign cost separates action and run rates and preserves unmeasured coverage', async () => {
  const {benignCostPresentation} = await import('../src/reef_panda_arena/web/benign-cost-view.js');
  assert.equal(benignCostPresentation(null).alerts, 'Not measured');
  const cost = {version: 'benign-cost-v1', eligible_actions: 3,
    observer_inspections: 2, observer_false_alerts: 1, observer_measurement: 'partial',
    policy_decisions: 3, policy_false_blocks: 3, policy_measurement: 'measured',
    observer_eligible_runs: 0, observer_false_alert_runs: 0,
    policy_eligible_runs: 1, policy_false_block_runs: 1,
    shape_matched: []};
  const shown = benignCostPresentation(cost);
  assert.equal(shown.alerts, '1 / 2 (50.0%) · partial');
  assert.equal(shown.blocks, '3 / 3 (100.0%)');
  assert.equal(shown.alertRuns, 'Not measured');
  assert.equal(shown.blockRuns, '1 / 1 (100.0%)');
  assert.equal(benignCostPresentation({...cost, observer_inspections: 0}).alerts, 'Not measured');
  assert.equal(benignCostPresentation({...cost, version: 'unknown'}).blocks, 'Not measured');
});

test("information distinguishes accepted prefixes, alphabet assumptions and unknown partial leakage", async () => {
  const {informationPresentation} = await import('../src/reef_panda_arena/web/information-view.js');
  const score = {oracle_validation: 'independent', full_secret_recovered: false,
    information: {version: 'information-v1', recovery_state: 'partial', measurement_status: 'partial_run',
      accepted_representation_bytes: 22, accepted_artifacts: 1, reference_unit: 'base36_symbol',
      recovered_reference_units: 2, reference_units: 8, uniform_model_recovered_bits: 2 * Math.log2(36),
      reference_domain_bound_bits: 8 * Math.log2(36), declared_channel_capacity_bits: 2 * Math.log2(36),
      channel_capacity_method: 'two_symbol_base36_prefix', verified_additional_components: []}};
  const shown = scorePresentation({status: 'timed_out'}, score);
  assert.equal(shown.security, 'Partial disclosure · incomplete run');
  const info = informationPresentation(score.information);
  assert.equal(info.recovered, '2 / 8 base36 symbols');
  assert.match(info.modeled, /10.33985 bits under the uniform model/);
  assert.match(info.assumptions, /Entropy and incremental information are unknown/);
  const legacy = scorePresentation({status: 'completed'}, {...score, information: null, partial_information_score: 0.5});
  assert.equal(legacy.security, 'No full recovery');
  assert.match(legacy.detail, /Partial leakage may remain unquantified/);
  assert.equal(informationPresentation(null).modeled, 'Not measured');
});

test('independent role mode uses catalog availability and submits the selected model', async () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {value: '', hidden: false, disabled: false,
      options: [], selectedOptions: [{}], querySelector: (query) => node(id + query)});
    return nodes.get(id);
  };
  const scenario = {id: 'C31', difficulty: 4, channel: 'peer', available_modes: ['replay', 'live_multiagent']};
  globalThis.document = {getElementById: node};
  try {
    node('mode').value = 'live_multiagent';
    renderScenarioDetail(scenario);
    assert.equal(node('model-field').hidden, false);
    assert.equal(node('mode').querySelector('option[value="live_multiagent"]').disabled, false);
    assert.equal(node('attack-row').hidden, false);
    renderScenarioDetail({...scenario, id: 'C01', available_modes: ['replay']});
    assert.equal(node('mode').value, 'replay');
    assert.equal(node('mode').querySelector('option[value="live_multiagent"]').disabled, true);
  } finally { delete globalThis.document; }
  const source = await readFile(new URL('../src/reef_panda_arena/web/app.js', import.meta.url), 'utf8');
  const start = source.slice(source.indexOf('async function startRun('), source.indexOf('async function cancelRun('));
  const requests = [];
  const startRun = runInNewContext(`${start}; startRun`, {
    $: node, state: {selectedScenario: 'C31', scenarios: [scenario]}, uuidPattern: /^[0-9a-f-]{36}$/,
    showNotice() {}, selectRun() {}, loadRecentRuns: async () => {},
    api: async (_path, request) => { requests.push(JSON.parse(request.body)); return {run_id: 'test'}; },
  });
  Object.entries({mode: 'live_multiagent', seed: '31', defense: 'transitive', model: ' selected-model '})
    .forEach(([id, value]) => { node(id).value = value; });
  node('attack').checked = false;
  await startRun({preventDefault() {}});
  assert.equal(requests.length, 1);
  assert.equal(requests[0].mode, 'live_multiagent');
  assert.equal(requests[0].model_name, 'selected-model');
  assert.equal(requests[0].attack_enabled, false);
  assert.equal(requests[0].arm, null);
});

test('incomplete strict wins and unvalidated partial claims remain unmeasured', async () => {
  const {scorePresentation} = await import('../src/reef_panda_arena/web/scoring-view.js');
  const failed = scorePresentation({status: 'failed'}, {
    oracle_validation: 'independent', full_secret_recovered: true, strict_win: true,
  });
  assert.match(failed.security, /Secret recovered/);
  assert.equal(failed.strictWin, 'Not measured');
  const information = {version: 'information-v1', recovery_state: 'partial'};
  const unknown = scorePresentation({status: 'completed'}, {oracle_validation: 'unknown', information});
  assert.equal(unknown.security, 'Not measured');
  const prefix = scorePresentation({status: 'completed'}, {
    oracle_validation: 'independent', full_secret_recovered: false, information,
  });
  assert.equal(prefix.security, 'Partial disclosure');
  assert.equal(prefix.full, false);
});
