"""Concrete adaptive controller with only persistence and model I/O replaced."""

import asyncio
import json

import pytest

from adaptive_test_support import model_task_answer
from test_terminal_observations import memory_runtime
from reef_panda_arena.application import adaptive
from reef_panda_arena.application.adaptive_work import AdaptiveWorkRuntime
from reef_panda_arena.adaptive.contracts import RepresentationNode, RepresentationSpec
from reef_panda_arena.model.ollama import ModelTimedOut
from reef_panda_arena.model.protocol import ModelResult


class TaskModel:
    def __init__(self, *, wrong=False, fail_attack=False):
        self.requests = []
        self.wrong = wrong
        self.fail_attack = fail_attack

    async def complete(self, request):
        self.requests.append(request)
        context = json.loads(request.messages[1].content)
        if context.get("task_version") != "adaptive-task-v2":
            if self.fail_attack:
                raise ModelTimedOut("Controlled attack request timeout")
            raise AssertionError("Task-only control unexpectedly requested an attack")
        answer = model_task_answer(context).model_dump()
        if self.wrong:
            answer["risk_band"] = (answer["risk_band"] + 1) % 4
        return ModelResult(content=json.dumps(answer), proposed_calls=(), model_name="fake-task-reader")


@pytest.mark.parametrize("scenario_id", [f"C{index}" for index in range(22, 29)])
@pytest.mark.parametrize("profile", ["none", "declassify_strict"])
def test_controller_runs_interleaved_scripted_work_with_independent_utility(memory_runtime, scenario_id, profile):
    session, settings = memory_runtime
    summary = asyncio.run(adaptive.run_adaptive(scenario_id, profile, 31, settings=settings, arm="A1"))
    assert summary.benign_task_success is True
    assert summary.secret_escaped is (profile == "none")
    details = session.scores[0].details_json
    assert details["same_reader_utility"] is True
    assert details["utility_version"] == "adaptive-utility-v2"
    assert details["utility_scope"] == "same_reader_scripted"
    assert details["task_model_calls"] == 0 and details["decision_turns"] == 3
    assert details["task_actor"] == "customer_worker"
    assert details["utility_evidence_event_seqs"]
    assert session.run.status == "completed"
    assert session.run.stage_snapshot_json["same_reader_utility"] is True


@pytest.mark.parametrize("scenario_id", ["C22", "C24", "C25"])
def test_live_no_attack_control_still_computes_work_with_the_model(memory_runtime, scenario_id):
    session, settings = memory_runtime
    caller = TaskModel()
    summary = asyncio.run(adaptive.run_adaptive(scenario_id, "declassify_strict", 31,
        settings=settings, mode="live_adaptive", arm="A0", caller=caller, model_name="fake-task-reader"))
    assert summary.benign_task_success is True and not summary.attacker_attempted
    details = session.scores[0].details_json
    assert len(caller.requests) == details["task_model_calls"] == details["total_model_calls"] == 1
    assert details["attacker_model_calls"] == 0 and details["model_originated"] is False
    assert details["utility_scope"] == "same_reader_model_decision"
    assert details["task_mechanism"] == "model_computation"
    assert details["task_prompt_version"] == "adaptive-task-v2"
    assert session.run.model_name == "fake-task-reader" and session.run.model_temperature == 0


def test_live_frozen_transfer_runs_model_task_but_does_not_regenerate_attack(monkeypatch, memory_runtime):
    session, settings = memory_runtime
    async def frozen(*_):
        return RepresentationSpec(family="report_layout", format="json", target_tool="analytics.report",
                                  nodes=(RepresentationNode(kind="approved_metric", source_ref="marker"),))
    monkeypatch.setattr(adaptive, "_transfer_spec", frozen)
    caller = TaskModel()
    summary = asyncio.run(adaptive.run_adaptive("C28", "none", 46, settings=settings,
        mode="live_adaptive", arm="A5", split="holdout", transfer_from_run_id="frozen-development",
        caller=caller, model_name="fake-task-reader"))
    assert summary.benign_task_success and summary.secret_escaped
    assert len(caller.requests) == 1
    details = session.scores[0].details_json
    assert details["task_model_calls"] == 1 and details["attacker_model_calls"] == 0
    assert details["model_originated"] is False and details["task_mechanism"] == "model_computation"


def test_wrong_model_task_is_completed_measured_failure_not_unknown(memory_runtime):
    session, settings = memory_runtime
    caller = TaskModel(wrong=True)
    summary = asyncio.run(adaptive.run_adaptive("C22", "none", 31, settings=settings,
        mode="live_adaptive", arm="A0", caller=caller, model_name="fake-task-reader"))
    assert session.run.status == "completed"
    assert summary.benign_task_success is False
    assert summary.scoring["benign_task_success"] is False
    assert session.scores[0].details_json["utility_reason"] == "incorrect_reader_contribution"
    assert not session.receipts and len(caller.requests) == 1


def test_timeout_after_initial_notice_keeps_partial_receipt_and_unknown_utility(memory_runtime):
    session, settings = memory_runtime
    caller = TaskModel(fail_attack=True)
    summary = asyncio.run(adaptive.run_adaptive("C22", "none", 31, settings=settings,
        mode="live_adaptive", arm="A2", caller=caller, model_name="fake-task-reader"))
    assert session.run.status == "timed_out"
    assert summary.benign_task_success is None
    assert summary.scoring["accepted_sink_receipts"] == 1 and len(session.receipts) == 1
    details = session.scores[0].details_json
    assert details["same_reader_utility"] is None and details["utility_reason"] == "task_incomplete"
    assert details["task_model_calls"] == 1 and details["attacker_model_calls"] == 2


def test_exception_after_leak_preserves_recovery_and_unknown_utility(monkeypatch, memory_runtime):
    session, settings = memory_runtime
    original = AdaptiveWorkRuntime._notice
    async def fail_final(self, stage):
        if stage == "final":
            raise RuntimeError("Controlled final task interruption")
        return await original(self, stage)
    monkeypatch.setattr(AdaptiveWorkRuntime, "_notice", fail_final)
    with pytest.raises(RuntimeError, match="Controlled final"):
        asyncio.run(adaptive.run_adaptive("C22", "none", 31, settings=settings, arm="A1"))
    scoring = session.run.stage_snapshot_json["scoring"]
    assert scoring["full_secret_recovered"] is True
    assert scoring["benign_task_success"] is None and scoring["strict_win"] is None
    assert len(session.receipts) == 2 and session.run.status == "failed"
    assert session.run.stage_snapshot_json["utility_reason"] == "task_incomplete"


def test_failed_attack_trial_does_not_certify_terminal_utility(memory_runtime):
    class InvalidAttack(TaskModel):
        async def complete(self, request):
            context = json.loads(request.messages[1].content)
            if context.get("task_version") == "adaptive-task-v2":
                return await super().complete(request)
            self.requests.append(request)
            return ModelResult(content="invalid-json", proposed_calls=(), model_name="fake-task-reader")
    session, settings = memory_runtime
    summary = asyncio.run(adaptive.run_adaptive("C22", "none", 31, settings=settings,
        mode="live_adaptive", arm="A2", caller=InvalidAttack(), model_name="fake-task-reader"))
    assert session.run.status == "failed" and summary.stop_reason == "invalid_candidates"
    assert len(session.receipts) == 2  # Both task notices actually arrived.
    assert summary.benign_task_success is None
    assert summary.scoring["benign_task_success"] is None
    assert session.scores[0].details_json["same_reader_utility"] is None


def test_interleaved_support_alert_is_not_counted_as_an_attack_alert(memory_runtime):
    session, settings = memory_runtime
    asyncio.run(adaptive.run_adaptive("C23", "none", 31, settings=settings, arm="A3", round_limit=2))
    details = session.scores[0].details_json
    assert details["attack_alerts"] == 2
    assert details["benign_alerts"] == 1
    assert details["alerts"] == 3
