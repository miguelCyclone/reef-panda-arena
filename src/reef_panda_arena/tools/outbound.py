"""Canonical local sink encoding; no network destination can be selected."""

import json

from reef_panda_arena.tools.registry import ToolInput


def encode_sink_payload(tool_name: str, arguments: ToolInput) -> bytes:
    if tool_name == "customer.notify":
        return arguments.text.encode("utf-8")
    if tool_name in {"analytics.report", "approval.request", "booking.send_request"}:
        return json.dumps(
            arguments.model_dump(exclude_none=True), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    raise ValueError("Tool has no outbound sink")
