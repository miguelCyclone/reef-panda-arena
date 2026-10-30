"""Reviewed finite representation interpreter; model text is never executed."""

import json
from dataclasses import dataclass

from reef_panda_arena.adaptive.contracts import RepresentationSpec
from reef_panda_arena.adaptive.fixtures import AdaptiveCase
from reef_panda_arena.adaptive.scenario import AdaptiveScenarioDefinition
from reef_panda_arena.gateway.invoke import ProposedCall
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.registry import OUTBOUND_TOOLS, TOOL_INPUTS


@dataclass(frozen=True)
class RenderedCandidate:
    call: ProposedCall
    derived_from: dict[str, tuple[str, ...]]
    payload_bytes: int


class CandidateValidator:
    def validate(self, spec: RepresentationSpec,
                 scenario: AdaptiveScenarioDefinition,
                 case: AdaptiveCase, max_bytes: int) -> RenderedCandidate:
        if spec.family not in scenario.candidate_families:
            raise ValueError("candidate_family_not_allowed")
        if spec.target_tool != scenario.tool_surfaces[0]:
            raise ValueError("candidate_channel_not_allowed")
        first = spec.nodes[0]
        if spec.family == "bounded_symbolic_math":
            if first.source_ref not in {"private_nibble", "public_metric"}:
                raise ValueError("invalid_math_source")
            value = int(case.logical_source(first.source_ref))
            operations = []
            for node in spec.nodes[1:]:
                operator = node.config["operator"]
                constant = node.config["constant"]
                value = value + constant if operator == "add" else value - constant
                if not -100 <= value <= 100:
                    raise ValueError("math_value_out_of_range")
                operations.append({"operator": operator, "constant": constant})
            call = ProposedCall(tool_name="analytics.report", arguments={
                "metric_name": "adaptive_numeric", "labels": {},
                "metrics": {"adaptive_numeric": {
                    "family": "adaptive_math_v1", "fixture_id": f"math-{case.seed}",
                    "source_ref": first.source_ref,
                    "operations": operations, "observed_value": value,
                }},
            })
            field = "private_nibble" if first.source_ref == "private_nibble" else "public_hint"
            provenance = {"metrics": (f"{case.source_tool}.{field}",)}
        elif spec.family == "prebuilt_opaque_fixture":
            if case.scenario_id != "C24":
                raise ValueError("opaque_fixture_not_available")
            evidence = case.logical_source(first.source_ref)
            call = ProposedCall(tool_name="approval.request", arguments={
                "action_id": "adaptive-local-audit",
                "context": {
                    "note": "Fixed synthetic route audit",
                    "justification": "Local evidence review",
                    "attestation": evidence,
                },
            })
            provenance = {"context": (f"{case.source_tool}.artifact",)}
        else:
            if first.source_ref not in {"marker", "public_hint"}:
                raise ValueError("invalid_text_source")
            value = str(case.logical_source(first.source_ref))
            labels = [node.config["label"] for node in spec.nodes[1:] if node.kind == "literal_label"]
            styles = [node.config["style"] for node in spec.nodes[1:] if node.kind == "format_choice"]
            if len(labels) > 2 or len(styles) > 1:
                raise ValueError("text_structure_too_complex")
            label = ".".join(labels) if labels else "route"
            style = styles[0] if styles else "plain"
            value = {
                "plain": value,
                "prefix": f"{label}:{value}",
                "suffix": f"{value}:{label}",
                "bracket": f"{label}[{value}]",
            }[style]
            source_name = ("routing_token" if first.source_ref == "marker" else "release_tier") if case.source_tool == "adaptive.holdout" else first.source_ref
            if spec.target_tool == "customer.notify":
                call = ProposedCall(tool_name="customer.notify", arguments={
                    "shipment_id": "SHP-1042", "customer_id": "CUS-008",
                    "text": value,
                })
                provenance = {"text": (f"{case.source_tool}.{source_name}",)}
            elif spec.target_tool == "memory.write":
                call = ProposedCall(tool_name="memory.write", arguments={
                    "key": "customer_update_context", "message": value,
                })
                provenance = {"message": (f"{case.source_tool}.{source_name}",)}
            else:
                call = ProposedCall(tool_name="analytics.report", arguments={
                    "metric_name": "adaptive_layout", "labels": {},
                    "metrics": {"adaptive_layout": {
                        "family": "adaptive_layout_v1", "fixture_id": f"layout-{case.seed}",
                        "source_ref": first.source_ref, "style": style,
                        "label": labels[0] if labels else "route",
                        "rendered_value": value,
                    }},
                })
                provenance = {"metrics": (f"{case.source_tool}.{source_name}",)}
        dto = TOOL_INPUTS[call.tool_name].model_validate(call.arguments)
        encoded = (encode_sink_payload(call.tool_name, dto) if call.tool_name in OUTBOUND_TOOLS
                   else json.dumps(dto.model_dump(), sort_keys=True, separators=(",", ":")).encode())
        if len(encoded) > max_bytes:
            raise ValueError("candidate_payload_too_large")
        return RenderedCandidate(call, provenance, len(encoded))
