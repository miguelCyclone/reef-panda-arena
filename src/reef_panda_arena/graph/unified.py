"""Bounded LangGraph schedule for the unified ten-role workflow."""

from collections.abc import Callable
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class UnifiedState(TypedDict, total=False):
    run_id: str
    graph_steps: int
    task_complete: bool


def build_unified_graph(nodes: dict[str, Callable], *, attack_prepare: Callable,
                        attack_finish: Callable):
    expected = {f"A{i}" for i in range(10)}
    if set(nodes) != expected:
        raise ValueError("Unified graph requires exactly A0 through A9")
    graph = StateGraph(UnifiedState)
    for actor_id in sorted(expected):
        graph.add_node(actor_id, nodes[actor_id])
    graph.add_node("attack_prepare", attack_prepare)
    graph.add_node("attack_finish", attack_finish)
    schedule = ("A0", "A1", "A2", "attack_prepare", "A3", "A4", "A5",
                "A6", "A7", "A8", "A9", "attack_finish")
    graph.add_edge(START, schedule[0])
    for source, target in zip(schedule, schedule[1:]):
        graph.add_edge(source, target)
    graph.add_edge(schedule[-1], END)
    return graph.compile()
