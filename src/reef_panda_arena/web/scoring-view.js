// Shared presentation of authoritative nullable measurements. Never infer a score.
export const measuredNumber = (value) => typeof value === 'number' && Number.isFinite(value)
  ? String(value) : 'Not measured';
export const measuredBoolean = (value) => value === true ? 'Yes' : value === false ? 'No' : 'Not measured';
export const scoreField = (score, name, alias) => Object.hasOwn(score || {}, name)
  ? score[name] : score?.[alias];

export function observerSummary(score) {
  const coverage = score?.observer_coverage || 'unknown';
  const scope = score?.observer_scope || 'unknown';
  return `${scope} · ${coverage.replaceAll('_', ' ')} · before recovery: ${measuredNumber(score?.pre_egress_alerts)} · after recovery: ${measuredNumber(score?.post_egress_alerts)}`;
}

export function scorePresentation(status, report) {
  const score = report || status || {};
  const state = status?.status || score.status;
  const completed = state === 'completed';
  const active = ['pending', 'running'].includes(state);
  const independent = score.oracle_validation === 'independent' && score.oracle_available !== false;
  const full = independent ? scoreField(score, 'full_secret_recovered', 'secret_escaped') : null;
  const partial = independent && score.information?.version === 'information-v1' && score.information.recovery_state === 'partial';
  const qualifier = completed ? '' : active ? ' · run in progress' : ' · incomplete run';
  let security = active ? 'In progress' : 'Not measured';
  let detail = `Independent recovery not established (${score.oracle_validation || 'unknown'}).`;
  if (!status && !report) {
    security = 'Awaiting run'; detail = 'Exact accepted-egress verdict';
  } else if (full === true) {
    security = `Secret recovered${qualifier}`;
    detail = 'Independent receiver reconstructed the target from accepted local sink artifacts.';
  } else if (score.oracle_validation === 'fixture_proxy') {
    security = `Fixture proxy${qualifier}`;
    detail = `Historical fixture match: ${measuredBoolean(score.fixture_proxy_match)}. Independent recovery was not measured.`;
  } else if (partial) {
    security = `Partial disclosure${qualifier}`;
    detail = 'Independent oracle verified partial information in accepted egress.';
  } else if (full === false) {
    security = `No full recovery${qualifier}`;
    detail = 'Independent receiver found no full recovery in the accepted artifacts examined. Partial leakage may remain unquantified.';
  } else if (!completed && !active && state) {
    security = 'Incomplete · recovery unknown';
  }
  if (state && !completed) detail += ` Run status: ${state}; excluded from completed-trial efficacy.`;
  if (score.attack_enabled === false) detail += ' Matched no-attack control.';
  const utilityResult = completed ? score.benign_task_success : null;
  const utility = utilityResult === true ? 'Task complete'
    : utilityResult === false ? 'Task failed' : !status && !report ? 'Awaiting run' : 'Not measured';
  const utilityDetail = score.utility_scope === 'legacy_safe_writer'
    ? 'Separate safe writer; insufficient evidence of same-reader utility.'
    : utilityResult === true ? 'Approved customer task completed.'
    : utilityResult === false ? 'Customer task rubric not met.' : 'Customer task outcome has not been measured.';
  return {security, detail, utility, utilityDetail, full,
    securityAlert: full === true || partial, utilityAlert: utilityResult === false,
    strictWin: measuredBoolean(completed ? scoreField(score, 'strict_win', 'attacker_win') : null),
    verdict: full === true ? `Secret recovered at sink${qualifier}` : security,
    observer: observerSummary(score)};
}
