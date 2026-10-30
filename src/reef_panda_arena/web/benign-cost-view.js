// Action costs and completed-run denominators have different meanings.
const count = value => Number.isInteger(value) && value >= 0 && value <= 40;

function ratio(numerator, denominator, state) {
  if (!count(numerator) || !count(denominator) || denominator === 0 || numerator > denominator
      || !['measured', 'partial'].includes(state)) return 'Not measured';
  return `${numerator} / ${denominator} (${(100 * numerator / denominator).toFixed(1)}%)${state === 'partial' ? ' · partial' : ''}`;
}

export function benignCostPresentation(value) {
  const cost = value?.version === 'benign-cost-v1' ? value : {};
  const names = {numeric_array: 'Numeric array', numeric_scalar: 'Numeric scalar',
    encrypted_envelope: 'Encrypted envelope', aggregate: 'Aggregate',
    formula_choice: 'Formula choice', structured_narrative: 'Structured narrative'};
  const shapes = Array.isArray(cost.shape_matched) ? cost.shape_matched.slice(0, 8) : [];
  return {
    eligible: count(cost.eligible_actions) ? String(cost.eligible_actions) : 'Not measured',
    alerts: ratio(cost.observer_false_alerts, cost.observer_inspections, cost.observer_measurement),
    blocks: ratio(cost.policy_false_blocks, cost.policy_decisions, cost.policy_measurement),
    alertRuns: ratio(cost.observer_false_alert_runs, cost.observer_eligible_runs, 'measured'),
    blockRuns: ratio(cost.policy_false_block_runs, cost.policy_eligible_runs, 'measured'),
    shapes: shapes.filter(row => names[row.shape_group]).map(row =>
      `${names[row.shape_group]}: false alerts ${ratio(row.observer_false_alerts, row.observer_inspections, row.observer_measurement)}; false blocks ${ratio(row.policy_false_blocks, row.policy_decisions, row.policy_measurement)}`
    ).join(' · ') || 'No measured shape-matched task actions.',
  };
}
