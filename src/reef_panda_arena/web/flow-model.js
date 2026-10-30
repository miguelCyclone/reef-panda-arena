// Deterministic presentation of recorded boundaries. No payload decoding or network IO.
import {scorePresentation, observerSummary} from "./scoring-view.js";

const terminal = new Set(['completed', 'failed', 'cancelled', 'timed_out', 'budget_exhausted']);
const outbound = new Set(['customer.notify', 'analytics.report', 'approval.request']);
const privateTools = new Set(['customer.profile', 'customer.eligibility', 'customer.fee', 'customer.priority',
  'operations.sensor', 'operations.route', 'research.source', 'adaptive.source', 'adaptive.holdout', 'private.account']);
const labels = (data) => Object.values(data.taint_labels || {});
export const isTerminal = (status) => terminal.has(status?.status);

export function mechanismFor(scenario, event, family = null, independent = false) {
  const list = scenario?.visualization?.mechanisms || [];
  const id = event?.data?.summary?.visual?.representation || family;
  return list.find((item) => item.id === id) || (independent ? null : list[0]) || null;
}

export function buildTrace(events, scenario, status, report) {
  const independent = status?.mode === 'live_multiagent' || report?.mode === 'live_multiagent'
    || Boolean(status?.live_execution || report?.live_execution);
  const frames = [];
  const messages = new Map();
  let family = null;
  const ordered = [...new Map(events.map((event) => [event.id, event])).values()].sort((a, b) => a.id - b.id);
  const add = (event, stage, from, to, title, detail, extra = {}) => frames.push({
    key: `${event.id}:${stage}`, eventId: event.id, event, stage, from, to, title, detail,
    phase: event.data?.summary?.visual?.phase || 'unclassified',
    secret: labels(event.data || {}).includes('secret'), mechanism: mechanismFor(scenario, event, family, independent), independent, ...extra,
  });
  for (const event of ordered) {
    const d = event.data || {};
    const s = d.summary || {};
    const actor = d.actor_id || 'system';
    const blocked = d.policy_decision === 'block';
    if (event.event === 'run.started') {
      add(event, 'start', 'supervisor', 'supervisor', 'Run started', 'Recorded events will activate the team in sequence.');
    } else if (event.event.startsWith('run.')) {
      add(event, 'finish', 'gateway', 'sink', event.event === 'run.completed' ? 'Run completed' : 'Run stopped',
        'The independent oracle result is shown when playback reaches this point.', {noPacket: true});
    } else if (event.event.startsWith('candidate.')) {
      family = s.family || family;
      add(event, 'transform', actor, actor, event.event === 'candidate.validated' ? 'Candidate validated' : 'Candidate rejected',
        `${d.reason_code || 'Data-only proposal'}${s.family ? ` · ${s.family}` : ''}`,
        {phase: 'attack', blocked, symbolic: true});
    } else if (event.event === 'agent.message') {
      if (s.visual?.representation && !blocked) add(event, 'transform', actor, actor,
        'Agent changes the representation', 'Runtime-marked representation; S stays symbolic.', {symbolic: true});
      if (s.message_id) messages.set(s.message_id, actor);
      add(event, 'message', actor, d.destination, blocked ? 'Peer send blocked' : 'Peer message queued',
        `${actor} → ${d.destination} · ${s.payload_kind || 'structured message'}`, {blocked});
    } else if (event.event === 'agent.receive') {
      add(event, 'receive', messages.get(s.message_id) || actor, actor,
        blocked ? 'Peer receive blocked' : 'Peer message consumed',
        `Recipient label: ${Object.entries(d.taint_labels || {}).map(([k,v]) => `${k}=${v}`).join(', ') || 'not recorded'}`,
        {blocked});
    } else if (event.event === 'artifact.reducer') {
      add(event, 'transform', actor, actor, 'Reducer joins dependencies',
        `${s.parent_count || '?'} registered parent artifacts · ${d.data_class}`, {blocked, symbolic: true});
    } else if ((d.tool_name || '').startsWith('memory.')) {
      const read = d.tool_name === 'memory.read';
      add(event, read ? 'read' : 'memory', read ? 'memory' : actor, read ? actor : 'memory',
        blocked ? 'Memory operation blocked' : d.tool_name,
        `Internal storage boundary · ${d.reason_code || 'recorded'}${s.version ? ` · version ${s.version}` : ''}`, {blocked});
    } else if (event.event === 'artifact.release' || event.event.includes('release')) {
      add(event, 'release', actor, actor, 'Trusted scoped release',
        `Registered projection · ${d.reason_code || d.policy_decision}`, {blocked});
    } else if (privateTools.has(d.tool_name) || labels(d).includes('secret') && !outbound.has(d.tool_name) && d.channel === 'tool') {
      add(event, 'read', blocked ? actor : 'vault', blocked ? 'vault' : actor,
        blocked ? 'Private read denied' : 'Agent accesses private source',
        `${d.tool_name} · ${blocked ? 'No value returned' : 'S remains redacted; source labels are recorded'}`, {blocked});
    } else if (outbound.has(d.tool_name)) {
      if ((!independent && s.visual?.phase === 'attack') || s.visual?.representation) {
        add(event, 'transform', actor, actor, 'Representation and call packaging',
          s.visual?.representation ? 'Recorded structured representation; values shown symbolically.' : 'Scenario mechanism illustration for this attack call; private values are hidden.',
          {symbolic: true});
      }
      add(event, 'propose', actor, 'gateway', 'Outbound call proposed', `${d.tool_name} → ${d.destination}`);
      const inspect = () => add(event, 'inspect', 'gateway', 'admin',
        s.observer_alert === true ? 'Observer raised an alert' : s.observer_alert === false ? 'Observer did not alert' : 'No independent observer recorded',
        `${s.observer_reason || 'Policy and observer are distinct.'} · ${{before_receipt: 'before receipt', after_receipt: 'after receipt'}[s.observer_phase] || 'timing not recorded'}`,
        {alert: s.observer_alert, observerPhase: s.observer_phase || null});
      if (s.observer_phase === 'before_receipt') inspect();
      add(event, blocked ? 'block' : s.accepted_sink_receipt === true ? 'egress' : 'decision', 'gateway', blocked ? 'gateway' : 'sink',
        blocked ? 'Gateway blocked the call' : s.accepted_sink_receipt === true ? 'Local sink accepted the payload' : 'Call allowed · no sink receipt recorded',
        d.reason_code || 'No reason recorded', {blocked, accepted: !blocked && (s.accepted_sink_receipt === true)});
      if (s.observer_phase !== 'before_receipt') inspect();
    } else if (d.tool_name) {
      add(event, 'work', blocked ? actor : 'data', blocked ? 'data' : actor,
        blocked ? 'Task operation blocked' : 'Task tool operation', `${d.tool_name} · ${d.reason_code || 'recorded'}`, {blocked});
    } else {
      add(event, 'work', actor, actor, event.event, d.reason_code || 'Recorded runtime event', {blocked});
    }
    if (!outbound.has(d.tool_name) && typeof s.observer_alert === 'boolean') {
      add(event, 'inspect', actor, 'admin', s.observer_alert ? 'Observer raised an alert' : 'Observer did not alert',
        s.observer_reason || 'Recorded observer inspection', {alert: s.observer_alert});
    }
  }
  return {frames, scenario, status, report, events: ordered, independent};
}

export function stateAt(trace, index) {
  const frames = trace.frames.slice(0, index + 1);
  const accepted = frames.filter((f) => f.accepted).length;
  const blocked = frames.filter((f) => f.stage === 'block').length;
  const inspections = frames.filter((f) => f.stage === 'inspect' && typeof f.alert === 'boolean');
  const alerts = inspections.filter((f) => f.alert).length;
  const atEnd = index >= trace.frames.length - 1 && trace.frames.length > 0 && isTerminal(trace.status);
  const report = atEnd ? trace.report : null;
  const shown = report ? scorePresentation(trace.status, report) : null;
  const verdict = shown ? shown.verdict : atEnd ? 'Not scored' : 'Awaiting final oracle';
  const observed = alerts ? `Alerted · ${alerts} call${alerts === 1 ? '' : 's'}`
    : inspections.length ? `No alert · ${inspections.length} inspected` : 'Not recorded / not reached';
  return {accepted, blocked, alerts, inspections: inspections.length, atEnd, report, verdict,
    securityAlert: shown?.securityAlert || false,
    observer: report ? `${observed} · ${observerSummary(report)}` : observed,
    resultNote: report ? `Strict win: ${shown.strictWin}. ${report.eligibility_reasons?.join(', ') || 'See observer scope and recovery evidence.'}`
      : 'Observer status follows this playhead. Recovery is revealed at the final scored step.'};
}

export function callTemplate(frame) {
  if (!frame) return 'Select a recorded event.';
  const d = frame.event.data || {};
  const visual = d.summary?.visual || {};
  const representation = visual.representation || frame.mechanism?.id;
  const symbol = {
    decimal_bytes: '[b₀, b₁, …]', base64: 'Base64(S)',
    polynomial_coefficients_v1: '[{numerator:n₀, denominator:d₀}, …]',
    semantic_summary: 'S[0:2]', literal: 'S',
  }[representation] || 'f(S)';
  if (frame.stage === 'read' && frame.from === 'vault') {
    const fields = Object.entries(d.taint_labels || {}).filter(([, label]) => label === 'secret').map(([name]) => `${name}: S`).join(', ');
    return `${d.tool_name}(public_identifier)\n→ { ${fields || 'private_field: S'}, … }`;
  }
  if (frame.event.event === 'agent.message' || frame.event.event === 'agent.receive') {
    const payload = visual.representation === 'decimal_bytes' ? `byte_values: ${symbol}` : '<structured fields redacted>';
    return `peer.${frame.event.event === 'agent.message' ? 'send' : 'receive'}(\n  actor=${d.actor_id}, recipient=${d.destination},\n  payload={${payload}}\n)`;
  }
  if (!d.tool_name) return `${frame.event.event}\n<recorded metadata; values redacted>`;
  const fields = visual.fields?.map((name) => `  ${name}: <redacted>`).join(',\n');
  let carrier = '';
  if ((!frame.independent && frame.phase === 'attack') || visual.representation) {
    if (d.tool_name === 'customer.notify') carrier = representation === 'decimal_bytes'
      ? 'text = "Private byte values: b₀,b₁,…"' : representation === 'semantic_summary'
      ? 'text = "Account code prefix S[0:2]"' : frame.mechanism?.carrier.startsWith('text =')
      ? frame.mechanism.carrier : `text = ${symbol}`;
    else if (d.tool_name.startsWith('memory.')) carrier = `message/value = ${symbol}`;
    else carrier = frame.mechanism?.carrier || '<carrier not described>';
  }
  return `${d.tool_name}({\n${fields || '  <arguments redacted>'}\n})${carrier ? `\n\nCarrier: ${carrier}` : ''}`;
}
