"""Symbolic visual coverage and confidentiality at the telemetry boundary."""

import json

from reef_panda_arena.gateway.invoke import TrustedContext
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.telemetry.call_shape import call_shape
from reef_panda_arena.telemetry.visual_catalog import describe_scenario


def test_all_registered_scenarios_have_truthful_symbolic_descriptions():
    loader = ScenarioLoader()
    descriptions = {sid: describe_scenario(loader.load(sid)) for sid in loader.list_ids()}
    assert len(descriptions) == 44
    for description in descriptions.values():
        assert description.mechanisms
        assert all(m.formula and m.explanation and m.carrier for m in description.mechanisms)
        assert set(description.compromised_roles) <= {a.id for a in description.agents}
    assert len(descriptions['C32'].agents) == 10
    assert descriptions['C32'].mechanisms[0].id == 'decimal_bytes'
    assert descriptions['C40'].mechanisms[0].formula == 'f(S) = S[0:2]'
    assert 'P(i) = bᵢ' in descriptions['C03'].mechanisms[0].formula
    assert descriptions['C13'].mechanisms[0].implementation == 'trusted fixture construction; independent decoding'


def test_visual_call_metadata_never_serializes_values_or_arbitrary_keys():
    secret = 'PRIVATE_SENTINEL_749'
    context = TrustedContext('run', 'customer_worker', 'customer_worker', operation_id='adaptive-candidate-0')
    shape = call_shape(context, 'analytics.report', {
        secret: secret,
        'metrics': {'adaptive_numeric': {
            'operations': [{'operator': 'add', 'constant': secret}, {'operator': secret}],
            'observed_value': secret,
        }},
        'labels': {secret: secret},
    })
    assert secret not in json.dumps(shape)
    assert shape['operators'] == ['add', 'unknown']
    assert shape['phase'] == 'attack'
    assert shape['representation'] == 'bounded_symbolic_math'
