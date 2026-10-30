"""Allowlisted structural telemetry: no argument values or encoded secret bytes."""


def trace_phase(context) -> str:
    if context.trace_phase in {"attack", "benign", "control"}:
        return context.trace_phase
    operation = context.operation_id or ""
    if operation.startswith(("attack", "suspect", "adaptive-candidate", "adaptive-peer", "memory-", "chunk-", "choice-", "positive-raw")):
        return "attack"
    return "unclassified"


def call_shape(context, tool_name: str, arguments: dict) -> dict:
    shape = {"phase": trace_phase(context)}
    if context.trace_representation in {"decimal_bytes", "semantic_summary", "literal"}:
        shape["representation"] = context.trace_representation
    # Only schema keys known to this application are published, never arbitrary keys.
    known = {"shipment_id", "customer_id", "text", "metrics", "labels", "context",
             "action_id", "metric_name", "key", "message", "case_id"}
    shape["fields"] = sorted(set(arguments) & known)
    metrics = arguments.get("metrics")
    if isinstance(metrics, dict):
        representations = {
            "byte_values": "decimal_bytes", "poly_coefficients": "polynomial_coefficients_v1",
            "spectral_summary": "fourier_fixture_v1", "basis_summary": "finite_orthogonal_basis_fixture",
            "aggregate_summary": "finite_aggregate_differencing_fixture",
            "formula_choice": "finite_semantically_equivalent_formula_fixture",
            "adaptive_numeric": "bounded_symbolic_math", "adaptive_layout": "report_layout",
        }
        for field, representation in representations.items():
            if field in metrics:
                shape.update(representation=representation, carrier=f"metrics.{field}")
                value = metrics[field]
                if field == "adaptive_numeric" and isinstance(value, dict):
                    operations = value.get("operations")
                    if isinstance(operations, list) and len(operations) <= 16:
                        shape["operators"] = [
                            op["operator"] if isinstance(op, dict) and op.get("operator") in {"add", "subtract"} else "unknown"
                            for op in operations
                        ]
                if field == "adaptive_layout" and isinstance(value, dict):
                    if value.get("style") in {"plain", "prefix", "suffix", "bracket"}:
                        shape["style"] = value["style"]
                break
    return shape
