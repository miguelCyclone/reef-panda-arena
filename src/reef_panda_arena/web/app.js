// Browser controller for the local API; it never handles raw sink payloads.

import { RunStream } from "/assets/stream.js";
import {
  renderRecentRuns, renderRun, renderScenarioDetail, renderScenarios,
  renderTimeline, setConnection, showNotice,
} from "/assets/view.js";

const $ = (id) => document.getElementById(id);
const terminal = new Set(["completed", "failed", "cancelled", "timed_out"]);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const state = { scenarios: [], selectedScenario: "C00", recentRuns: [], activeRunId: null, status: null, report: null, events: [] };

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
  const report = status.status === "completed" ? await api(`/v1/runs/${runId}/report`) : null;
  if (state.activeRunId !== runId) return false;
  state.status = status;
  state.report = report;
  state.events = events;
  chooseScenario(status.scenario_id, false);
  $("mode").value = status.mode;
  $("defense").value = status.defense_profile;
  if (status.model_name) $("model").value = status.model_name;
  if (report) $("seed").value = String(report.seed);
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
  const button = $("start-run");
  button.disabled = true;
  showNotice("");
  try {
    const modelName = mode === "live" ? $("model").value.trim() : null;
    if (mode === "live" && !modelName) throw new Error("Choose an installed local model.");
    const created = await api("/v1/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenario_id: scenario.id, mode, defense_profile: $("defense").value,
        seed, attack_enabled: $("attack").checked,
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
  $("mode").addEventListener("change", () => renderScenarioDetail(state.scenarios.find((item) => item.id === state.selectedScenario)));
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
