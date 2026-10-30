// Quantities have distinct units; an alphabet model is never measured entropy.
const number = (value) => typeof value === 'number' && Number.isFinite(value)
  ? String(Math.round(value * 100000) / 100000) : 'Not measured';

export function informationPresentation(value) {
  if (value?.version !== 'information-v1') return {
    state: 'Not measured', bytes: 'Not measured', recovered: 'Not measured',
    domain: 'Not measured', capacity: 'Not measured', modeled: 'Not measured',
    components: 'Not measured', positions: 'Not measured', assumptions: 'Historical or absent information evidence. Partial leakage remains unknown.',
  };
  const states = {full: 'Full reference recovered', partial: 'Verified partial disclosure',
    no_accepted_egress: 'No accepted egress', unquantified: 'Accepted egress; partial leakage unquantified'};
  const unit = value.reference_unit === 'base36_symbol' ? 'base36 symbols' : 'finite values';
  return {
    state: `${states[value.recovery_state] || 'Not measured'}${value.measurement_status === 'partial_run' ? ' · incomplete run' : ''}`,
    bytes: `${number(value.accepted_representation_bytes)} bytes in ${number(value.accepted_artifacts)} accepted artifacts`,
    recovered: `${number(value.recovered_reference_units)} / ${number(value.reference_units)} ${unit}`,
    positions: value.recovered_source_bit_positions == null ? 'Not measured'
      : `${number(value.recovered_source_bit_positions)} ASCII representation positions (not entropy bits)`,
    domain: `${number(value.reference_domain_bound_bits)} bits (reference alphabet bound)`,
    capacity: value.declared_channel_capacity_bits == null ? 'Not quantified'
      : `${number(value.declared_channel_capacity_bits)} bits (${value.channel_capacity_method.replaceAll('_', ' ')})`,
    modeled: value.uniform_model_recovered_bits == null ? 'Not measured'
      : `${number(value.uniform_model_recovered_bits)} bits under the uniform model`,
    components: value.verified_additional_components?.includes('exact_fee_cents')
      ? `Exact fee recovered; ${number(value.additional_component_model_bits)} model bits if uniform over 0–10000 with no prior knowledge` : 'No additional component verified',
    assumptions: 'Model assumes independent uniform reference symbols and no prior knowledge. Entropy and incremental information are unknown. Capacity covers the named representation only; other leakage is not exhaustively assessed.',
  };
}
