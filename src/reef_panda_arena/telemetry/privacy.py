"""Keep actual graph execution local even under inherited tracing contexts."""

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from langchain_core.runnables.config import var_child_runnable_config
from langchain_core.tracers.context import tracing_v2_callback_var
from langsmith import tracing_context


@contextmanager
def no_external_tracing() -> Iterator[None]:
    """Disable environment and inherited exporters; restore caller context.

    LangChain's explicit tracer context takes precedence over LangSmith's
    enabled flag. Inherited runnable callbacks are a separate export path.
    Context variables isolate concurrent callers without environment changes.
    """
    tracer_token = tracing_v2_callback_var.set(None)
    config_token = var_child_runnable_config.set(None)
    try:
        with tracing_context(enabled=False, parent=False):
            yield
    finally:
        var_child_runnable_config.reset(config_token)
        tracing_v2_callback_var.reset(tracer_token)


async def invoke_graph_privately(
    build_graph: Callable[[], Any], inputs: Any, *,
    config: dict[str, Any] | None = None,
) -> Any:
    """Compile and invoke inside one private scope with no root callbacks."""
    with no_external_tracing():
        safe_config = dict(config or {})
        safe_config["callbacks"] = []
        return await build_graph().ainvoke(inputs, config=safe_config)
