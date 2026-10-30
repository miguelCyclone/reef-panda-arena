// Browser controller for the local API; it never handles raw sink payloads.

import { FlowPlayer } from "/assets/flow-player.js";
import { RunStream } from "/assets/stream.js";
import {
  renderRecentRuns, renderRun, renderScenarioDetail, renderScenarios,
  renderTimeline, setConnection, showNotice,
} from "/assets/view.js";

const $ = (id) => document.getElementById(id);
const terminal = new Set(["completed", "failed", "cancelled", "timed_out", "budget_exhausted"]);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const state = { scenarios: [], selectedScenario: "C00", recentRuns: [], activeRunId: null, status: null, report: null, events: [] };

const flow = new FlowPlayer();

async function api(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((item) => item.msg).join("; ");
    } catch { /* Keep the status-only error. */ }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function paint() {
  flow.update(state.scenarios.find((item) => item.id === (state.status?.scenario_id || state.selectedScenario)), state.status, state.report, state.events);
  renderRun(state.status, state.report, state.events);
  renderTimeline(state.events);
  renderRecentRuns(state.recentRuns, state.activeRunId, selectRun);
}

function chooseScenario(id, recordInteraction = true) {
  const scenario = state.scenarios.find((item) => item.id === id);
  if (!scenario) return;
  state.selectedScenario = id;
  renderScenarios(state.scenarios, id, chooseScenario);
  renderScenarioDetail(scenario);
  if (!state.status) flow.update(scenario, null, null, []);
  if (recordInteraction) stream.touch();
}

async function loadRecentRuns() {
  state.recentRuns = await api("/v1/runs?limit=20");
  renderRecentRuns(state.recentRuns, state.activeRunId, selectRun);
}

async function loadEventHistory(runId) {
  let cursor = 0;
  const found = new Map();
  for (let page = 0; page < 2; page += 1) {
    const result = await api(`/v1/runs/${runId}/events?cursor=${cursor}&limit=100`);
    for (const event of result.events) found.set(event.id, event);
    if (result.next_cursor === null) break;
    cursor = result.next_cursor;
  }
  return [...found.values()].sort((a, b) => a.id - b.id);
}

async function recoverRun(runId) {
  let status;
  let events;
  try {
    [status, events] = await Promise.all([
      api(`/v1/runs/${runId}`), loadEventHistory(runId),
    ]);
  } catch (error) {
    if (state.activeRunId === runId && error.status === 404) showNotice("Run ID was not found.", true);
    throw error;
  }
  let report = null;
  if (terminal.has(status.status)) {
    try { report = await api(`/v1/runs/${runId}/report`); }
    catch (error) { if (error.status !== 409) throw error; }
  }
  if (state.activeRunId !== runId) return false;
  state.status = status;
  state.report = report;
  state.events = events;
  chooseScenario(status.scenario_id, false);
  $("mode").value = status.mode;
  $("defense").value = status.defense_profile;
  if (status.model_name) $("model").value = status.model_name;
  if (report) $("seed").value = String(report.seed);
  if (report?.arm && Number(status.scenario_id.slice(1)) >= 22 && Number(status.scenario_id.slice(1)) <= 28) $("adaptive-arm").value = report.arm;
  else if (report?.arm) $("arm").value = report.arm;
  if (report?.observer_profile && Number(status.scenario_id.slice(1)) >= 22) $("adaptive-reviewer").value = report.observer_profile;
  else if (report?.observer_profile) $("observer").value = report.observer_profile;
  if (report?.round_limit) $("adaptive-rounds").value = String(report.round_limit);
  if (report?.split) $("adaptive-split").value = report.split;
  if (report?.transfer_from_run_id) $("transfer-run-id").value = report.transfer_from_run_id;
  renderScenarioDetail(state.scenarios.find((item) => item.id === status.scenario_id));
  paint();
  return !terminal.has(status.status);
}

function onEvent(event) {
  if (!state.activeRunId || !Number.isSafeInteger(event.id)) return;
  const prior = new Map(state.events.map((item) => [item.id, item]));
  prior.set(event.id, event);
  state.events = [...prior.values()].sort((a, b) => a.id - b.id);
  if (event.event === "run.started" && state.status) state.status.status = "running";
  paint();
  if (["run.completed", "run.failed", "run.cancelled", "run.timed_out"].includes(event.event)) {
    void recoverRun(state.activeRunId).catch((error) => showNotice(error.message, true));
    void loadRecentRuns().catch((error) => showNotice(error.message, true));
  }
}

const stream = new RunStream({ onRecover: recoverRun, onEvent, onState: setConnection });

function selectRun(runId) {
  if (!uuidPattern.test(runId)) {
    showNotice("Enter a valid run UUID.", true);
    return;
  }
  showNotice("");
  state.activeRunId = runId;
  state.status = null;
  state.report = null;
  state.events = [];
  paint();
  history.replaceState(null, "", `?run=${encodeURIComponent(runId)}`);
  stream.connect(runId);
}

async function startRun(event) {
  event.preventDefault();
  const scenario = state.scenarios.find((item) => item.id === state.selectedScenario);
  const mode = $("mode").value;
  const seed = Number($("seed").value);
  if (!scenario || !scenario.available_modes.includes(mode) || !Number.isSafeInteger(seed) || seed < 0) {
    showNotice("Choose a supported scenario, mode, and nonnegative integer seed.", true);
    return;
  }
  const number = Number(scenario.id.slice(1));
  const extension = number >= 15 && number <= 21;
  const adaptive = number >= 22 && number <= 28;
  const arm = extension ? $("arm").value : adaptive ? $("adaptive-arm").value : null;
  const defense = $("defense").value;
  if (extension && ((["A0", "B0"].includes(arm) && defense !== "none") ||
      (!["A0", "B0"].includes(arm) && defense === "none"))) {
    showNotice("A0/B0 use None; A1/B1/H0/P0 require a defense profile.", true);
    return;
  }
  if (adaptive && mode === "live") {
    showNotice("Use Adaptive Ollama for C22–C28.", true);
    return;
  }
  if (adaptive && mode === "live_adaptive" && arm === "A1") {
    showNotice("A1 is a scripted replay control; choose A2, A3 or A4 for model research.", true);
    return;
  }
  if (adaptive && mode === "replay" && ["A2", "A4"].includes(arm)) {
    showNotice("A2 and A4 require Adaptive Ollama mode.", true);
    return;
  }
  const split = adaptive ? $("adaptive-split").value : "development";
  const transferId = adaptive && arm === "A5" ? $("transfer-run-id").value.trim() : null;
  if (adaptive && arm === "A5" && (number !== 28 || split !== "holdout" || !uuidPattern.test(transferId))) {
    showNotice("C28 A5 needs a completed development run UUID and the holdout split.", true);
    return;
  }
  const rounds = adaptive ? Number($("adaptive-rounds").value) : 8;
  if (adaptive && (!Number.isInteger(rounds) || rounds < 1 || rounds > 8)) {
    showNotice("Adaptive rounds must be 1–8.", true);
    return;
  }
  const button = $("start-run");
  button.disabled = true;
  showNotice("");
  try {
    const needsModel = mode === "live" || mode === "live_adaptive" || mode === "live_multiagent";
    const modelName = needsModel ? $("model").value.trim() : null;
    if (needsModel && !modelName) throw new Error("Choose an installed local model.");
    const created = await api("/v1/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenario_id: scenario.id, mode, defense_profile: defense,
        seed, attack_enabled: extension ? ["A0", "A1", "P0"].includes(arm) : adaptive ? arm !== "A0" : $("attack").checked,
        arm, observer_profile: extension ? $("observer").value : adaptive ? $("adaptive-reviewer").value : "metadata_schema",
        round_limit: rounds, split, transfer_from_run_id: transferId,
        model_name: modelName, temperature: 0,
      }),
    });
    selectRun(created.run_id);
    void loadRecentRuns().catch((error) => showNotice(error.message, true));
  } catch (error) {
    showNotice(error.message || "Unable to start run.", true);
  } finally {
    button.disabled = false;
  }
}

async function cancelRun() {
  if (!state.activeRunId) return;
  try {
    await api(`/v1/runs/${state.activeRunId}/cancel`, { method: "POST" });
    stream.stop();
    await recoverRun(state.activeRunId);
    await loadRecentRuns();
    setConnection("complete");
  } catch (error) {
    showNotice(error.message || "Unable to cancel run.", true);
  }
}

async function initialize() {
  $("run-form").addEventListener("submit", startRun);
  $("mode").addEventListener("change", () => {
    if ($("mode").value === "live_adaptive" && $("adaptive-arm").value === "A1") $("adaptive-arm").value = "A3";
    if ($("mode").value === "replay" && ["A2", "A4"].includes($("adaptive-arm").value)) $("adaptive-arm").value = "A1";
    renderScenarioDetail(state.scenarios.find((item) => item.id === state.selectedScenario));
  });
  $("adaptive-arm").addEventListener("change", () => renderScenarioDetail(state.scenarios.find((item) => item.id === state.selectedScenario)));
  $("cancel-run").addEventListener("click", cancelRun);
  $("resume-updates").addEventListener("click", () => stream.resume());
  $("refresh-runs").addEventListener("click", () => loadRecentRuns().catch((error) => showNotice(error.message, true)));
  $("open-run-form").addEventListener("submit", (event) => {
    event.preventDefault();
    selectRun($("open-run-id").value.trim());
  });
  window.addEventListener("pointerdown", () => stream.touch());
  window.addEventListener("keydown", () => stream.touch());
  try {
    state.scenarios = await api("/v1/scenarios");
    chooseScenario(state.scenarios[0]?.id || "C00");
    await loadRecentRuns();
    const linkedRun = new URLSearchParams(location.search).get("run");
    if (linkedRun && uuidPattern.test(linkedRun)) selectRun(linkedRun);
    else if (state.recentRuns.length) selectRun(state.recentRuns[0].run_id);
    else setConnection("ready");
  } catch (error) {
    setConnection("error");
    showNotice(error.message || "Local API unavailable.", true);
  }
}

void initialize();
