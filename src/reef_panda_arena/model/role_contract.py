"""Bounded declarative role decisions; runtime identity and provenance are absent."""

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, model_validator


RoleRejection = Literal["invalid_role_proposal", "invalid_decision_schema", "direct_tool_calls_unsupported",
                        "tool_not_permitted", "peer_route_not_permitted", "release_not_permitted",
                        "route_transport_not_permitted", "reader_contribution_not_permitted", "memory_not_permitted", "model_request_failed"]


ActorId = Literal["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"]


def bounded_data(value):
    """Validate only JSON data; no expression evaluation or executable extensions."""
    def visit(item, depth=0):
        if depth > 12:
            raise ValueError("Role data nesting exceeds its bound")
        if type(item) is dict:
            if len(item) > 16 or any(type(key) is not str or len(key) > 64 for key in item):
                raise ValueError("Role data object exceeds its bound")
            for child in item.values():
                visit(child, depth + 1)
        elif type(item) is list:
            if len(item) > 16:
                raise ValueError("Role data sequence exceeds its bound")
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str and len(item) > 2048:
            raise ValueError("Role data string exceeds its bound")
    visit(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(encoded.encode()) > 4096:
        raise ValueError("Role data exceeds its byte bound")
    return encoded


class StrictDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ToolAction(StrictDecision):
    kind: Literal["tool"]
    tool: Literal["shipment.lookup", "operations.incident", "private.account", "customer.notify"]
    arguments: dict[str, JsonValue] = Field(max_length=16)


class PeerAction(StrictDecision):
    kind: Literal["peer"]
    recipient: ActorId
    message_kind: Literal["artifact", "request"] = "artifact"
    payload: dict[str, JsonValue] = Field(min_length=1, max_length=16)


class ReaderContributionAction(StrictDecision):
    kind: Literal["reader_contribution"]
    source_input: str = Field(pattern=r"^input_[0-9]{1,2}$")
    category: Literal["standard", "priority"]
    service_hours: Literal[24, 48]
    action: Literal["monitor", "expedite"]


class ReleaseAction(StrictDecision):
    kind: Literal["release"]
    source_input: str = Field(pattern=r"^input_[0-9]{1,2}$")
    proposal_input: str = Field(pattern=r"^input_[0-9]{1,2}$")
    forward_to: Literal["A5"] | None = None


class ForwardRouteAction(StrictDecision):
    kind: Literal["forward_route"]
    source_input: str = Field(pattern=r"^input_[0-9]{1,2}$")
    recipient: Literal["A7"]


class StoreRouteAction(StrictDecision):
    kind: Literal["store_route"]
    source_input: str = Field(pattern=r"^input_[0-9]{1,2}$")


class MemoryAction(StrictDecision):
    kind: Literal["memory_read", "memory_write", "memory_compact"]
    key: Literal["approved_route", "customer_update_context"]
    value: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def write_has_value(self):
        if (self.kind == "memory_write") != (self.value is not None):
            raise ValueError("Memory action value disagrees with its operation")
        return self


class MemoryWriteAction(MemoryAction):
    kind: Literal["memory_write"]
    value: str = Field(max_length=2048)


class MemoryReadAction(MemoryAction):
    kind: Literal["memory_read", "memory_compact"]
    value: None = None


Action = Annotated[ToolAction | PeerAction | ReaderContributionAction | ReleaseAction | MemoryWriteAction | MemoryReadAction | StoreRouteAction | ForwardRouteAction, Field(discriminator="kind")]


class RoleDecision(StrictDecision):
    disposition: Literal["act", "refuse", "clarify", "finish"]
    reason: Literal["task_ready", "insufficient_information", "confidentiality", "unauthorized_request", "other"]
    actions: tuple[Action, ...] = Field(max_length=4)

    @model_validator(mode="after")
    def finite_effects(self):
        if self.disposition == "clarify":
            if len(self.actions) > 1 or any(not isinstance(action, PeerAction)
                    or action.message_kind != "request" for action in self.actions):
                raise ValueError("Clarification may only send one peer request")
        elif (self.disposition == "act") != bool(self.actions):
            raise ValueError("Only an acting decision may propose effects")
        bounded_data(self.model_dump(mode="json"))
        return self


class ActingDecision(RoleDecision):
    disposition: Literal["act"]
    actions: tuple[Action, ...] = Field(min_length=1, max_length=4)


class SilentDecision(RoleDecision):
    disposition: Literal["refuse", "finish"]
    actions: tuple[Action, ...] = Field(max_length=0)


class ClarificationAction(PeerAction):
    message_kind: Literal["request"]


class ClarifyingDecision(RoleDecision):
    disposition: Literal["clarify"]
    actions: tuple[ClarificationAction, ...] = Field(max_length=1)


# Express cross-field invariants in the provider schema as well as the runtime
# validator. A flat disposition enum incorrectly permits refusal plus actions.
DecisionOutput = TypeAdapter(Annotated[
    ActingDecision | SilentDecision | ClarifyingDecision, Field(discriminator="disposition")
])


def decision_output_schema(permissions=None, tool_argument_schemas=None):
    """Advertise exactly the runtime role capabilities, without granting any."""
    schema = DecisionOutput.json_schema()
    if permissions is None:
        return schema
    definitions = schema["$defs"]
    allowed = set()
    if permissions["tools"]:
        allowed.add("ToolAction")
        definitions["ToolAction"]["properties"]["tool"]["enum"] = permissions["tools"]
        if tool_argument_schemas is not None:
            # Each current role owns one tool; encode its real strict arguments,
            # rather than merely mentioning their schema in natural-language context.
            variants = []
            for tool in permissions["tools"]:
                variant = json.loads(json.dumps(definitions["ToolAction"]))
                variant["properties"]["tool"] = {"type": "string", "const": tool}
                variant["properties"]["arguments"] = tool_argument_schemas[tool]
                variants.append(variant)
            definitions["ToolAction"] = variants[0] if len(variants) == 1 else {"oneOf": variants}
    if permissions["peer_recipients"]:
        allowed.add("PeerAction")
        for name in ("PeerAction", "ClarificationAction"):
            definitions[name]["properties"]["recipient"]["enum"] = permissions["peer_recipients"]
    else:
        definitions["ClarifyingDecision"]["properties"]["actions"]["maxItems"] = 0
    for flag, name in (("can_submit_reader", "ReaderContributionAction"), ("can_release", "ReleaseAction"),
                       ("can_forward_route", "ForwardRouteAction"),
                       ("can_store_route", "StoreRouteAction")):
        if permissions[flag]:
            allowed.add(name)
    memory = [kind for flag, kind in (("can_read_memory", "memory_read"),
              ("can_write_memory", "memory_write"), ("can_compact_memory", "memory_compact"))
              if permissions[flag]]
    if "memory_write" in memory:
        allowed.add("MemoryWriteAction")
    read_kinds = [kind for kind in memory if kind != "memory_write"]
    if read_kinds:
        allowed.add("MemoryReadAction")
        definitions["MemoryReadAction"]["properties"]["kind"]["enum"] = read_kinds
    actions = definitions["ActingDecision"]["properties"]["actions"]["items"]
    actions["oneOf"] = [item for item in actions["oneOf"] if item["$ref"].split("/")[-1] in allowed]
    actions["discriminator"]["mapping"] = {
        kind: ref for kind, ref in actions["discriminator"]["mapping"].items()
        if ref.split("/")[-1] in allowed}
    return schema
