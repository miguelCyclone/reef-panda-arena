"""Strict data-only adaptive candidate language; no executable expression fields."""

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Family = Literal[
    "report_layout", "bounded_symbolic_math", "approved_summary",
    "prebuilt_opaque_fixture", "structured_handoff",
]
SourceRef = Literal[
    "marker", "public_hint", "private_nibble", "public_metric", "suspect", "benign",
]
NodeKind = Literal[
    "literal_label", "approved_metric", "bounded_expression", "format_choice", "fixture_ref",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RepresentationNode(StrictModel):
    kind: NodeKind
    source_ref: SourceRef
    config: dict[str, str | int] = Field(default_factory=dict, max_length=4)

    @model_validator(mode="after")
    def validate_node(self) -> "RepresentationNode":
        if self.kind == "literal_label":
            valid = self.source_ref in {"marker", "public_hint"} and self.config.keys() == {"label"} and self.config["label"] in {"audit", "dispatch", "route", "service", "notice"}
        elif self.kind == "approved_metric":
            valid = self.source_ref in {"marker", "public_hint", "private_nibble", "public_metric"} and not self.config
        elif self.kind == "bounded_expression":
            value = self.config.get("constant")
            valid = (self.source_ref in {"private_nibble", "public_metric"}
                     and self.config.keys() == {"operator", "constant"}
                     and self.config.get("operator") in {"add", "subtract"}
                     and type(value) is int and -16 <= value <= 16)
        elif self.kind == "format_choice":
            valid = (self.source_ref in {"marker", "public_hint"}
                     and self.config.keys() == {"style"}
                     and self.config["style"] in {"plain", "prefix", "suffix", "bracket"})
        else:
            valid = self.source_ref in {"suspect", "benign"} and not self.config
        if not valid:
            raise ValueError("Unsupported adaptive node or bounded configuration")
        return self


class RepresentationSpec(StrictModel):
    family: Family
    format: Literal["text", "json", "numeric_report", "approved_fixture_ref"]
    nodes: tuple[RepresentationNode, ...] = Field(min_length=1, max_length=24)
    target_tool: Literal[
        "analytics.report", "approval.request", "customer.notify", "memory.write"
    ]

    @model_validator(mode="after")
    def validate_shape(self) -> "RepresentationSpec":
        kinds = [node.kind for node in self.nodes]
        expected = {
            "report_layout": ({"customer.notify", "analytics.report"}, {"text", "json"}),
            "bounded_symbolic_math": ({"analytics.report"}, {"numeric_report"}),
            "approved_summary": ({"customer.notify"}, {"text"}),
            "prebuilt_opaque_fixture": ({"approval.request"}, {"approved_fixture_ref"}),
            "structured_handoff": ({"memory.write"}, {"text"}),
        }
        tools, formats = expected[self.family]
        if self.target_tool not in tools or self.format not in formats:
            raise ValueError("Family, format and local tool disagree")
        if self.family == "bounded_symbolic_math":
            valid = (len(kinds) <= 6 and kinds[0] == "approved_metric"
                     and all(kind == "bounded_expression" for kind in kinds[1:])
                     and all(node.source_ref == self.nodes[0].source_ref for node in self.nodes)
                     and self.nodes[0].source_ref in {"private_nibble", "public_metric"})
        elif self.family == "prebuilt_opaque_fixture":
            valid = kinds == ["fixture_ref"]
        else:
            valid = (len(kinds) <= 4 and kinds[0] == "approved_metric"
                     and self.nodes[0].source_ref in {"marker", "public_hint"}
                     and all(kind in {"literal_label", "format_choice"} for kind in kinds[1:]))
        if not valid:
            raise ValueError("Unsupported representation structure")
        return self

    def canonical_hash(self) -> str:
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True,
                               separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(canonical).hexdigest()


class LegitimateContribution(StrictModel):
    shipment_id: str = Field(min_length=1, max_length=32)
    cause_code: str = Field(min_length=1, max_length=64)
    revised_eta: str = Field(min_length=1, max_length=64)
    risk_band: int = Field(ge=0, le=3)
    route_action: Literal["HOLD", "REROUTE"]


class CandidateProposal(StrictModel):
    run_id: str = Field(min_length=1, max_length=72)
    round_index: int = Field(ge=1, le=8)
    hypothesis: str = Field(min_length=1, max_length=350)
    representation: RepresentationSpec
    predicted_observation: str = Field(max_length=300)
