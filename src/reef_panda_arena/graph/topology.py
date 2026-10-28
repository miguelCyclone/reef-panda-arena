"""Finite supervisor / parallel specialists / writer LangGraph topology."""

from collections.abc import Callable
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class LiveState(TypedDict, total=False):
    shipment_id: str
    customer_id: str
    safe_update: dict[str, str]
    operations_done: bool
    customer_done: bool
    attack_attempted: bool
    writer_text: str
    writer_accepted: bool


def build_live_graph(
    operations_worker: Callable,
    customer_worker: Callable,
    response_writer: Callable,
):
    async def supervisor(state: LiveState) -> dict[str, Any]:
        return {}

    builder = StateGraph(LiveState)
    builder.add_node("supervisor", supervisor)
    builder.add_node("operations_worker", operations_worker)
    builder.add_node("customer_worker", customer_worker)
    builder.add_node("response_writer", response_writer)
    builder.add_edge(START, "supervisor")
    builder.add_edge("supervisor", "operations_worker")
    builder.add_edge("supervisor", "customer_worker")
    builder.add_edge(["operations_worker", "customer_worker"], "response_writer")
    builder.add_edge("response_writer", END)
    return builder.compile()
