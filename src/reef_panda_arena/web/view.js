import {informationPresentation} from "./information-view.js";
import {benignCostPresentation} from "./benign-cost-view.js";
// Render only sanitized API fields with text nodes.
import {measuredNumber, measuredBoolean, scoreField, scorePresentation} from "./scoring-view.js";

const element = (id) => document.getElementById(id);
const terminal = new Set(["completed", "failed", "cancelled", "timed_out", "budget_exhausted"]);

export function showNotice(message, isError = false) {
  const notice = element("notice");
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = !message;
}

export function setConnection(state) {
  const label = {
    connecting: "Connecting", live: "Live updates", retrying: "Reconnecting in 30s",
    paused: "Updates paused", complete: "Run finished", ready: "Local API ready",
    error: "Connection issue",
  }[state] || "Local API";
  const node = element("connection-state");
  node.textContent = label;
  node.className = `connection-state ${["retrying", "paused"].includes(state) ? "warn" : state === "error" ? "error" : ""}`;
  element("resume-updates").hidden = state !== "paused";
}

export function renderScenarios(scenarios, selectedId, onChoose) {
  const grid = element("scenario-grid");
  const fragment = document.createDocumentFragment();
  for (const scenario of scenarios) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `scenario-card ${scenario.id === selectedId ? "selected" : ""}`;
    button.setAttribute("aria-pressed", String(scenario.id === selectedId));
    const number = document.createElement("span");
    number.className = "scenario-number";
    number.textContent = scenario.id;
    const copy = document.createElement("span");
    copy.className = "scenario-copy";
    const title = document.createElement("strong");
    title.textContent = scenario.title;
    const level = document.createElement("small");
    level.textContent = `LEVEL ${scenario.difficulty}`;
    copy.append(title, level);
    button.append(number, copy);
    button.addEventListener("click", () => onChoose(scenario.id));
    fragment.append(button);
  }
  grid.replaceChildren(fragment);
}

export function renderScenarioDetail(scenario) {
  const number = Number(scenario?.id.slice(1));
  const extension = number >= 15 && number <= 21;
  const adaptive = number >= 22 && number <= 28;
  const unified = number >= 29 && number <= 43;
  const seedNote = unified ? " · matched seeds: 31–33"
    : number === 28
    ? " · dev seeds: 31–35; holdout: 46–50"
    : adaptive ? " · dev seeds: 31–35"
    : number >= 10 ? " · fixture seeds: 1, 23, 31–50" : "";
  element("scenario-detail").textContent = scenario
    ? `Level ${scenario.difficulty} · ${scenario.channel} · ${scenario.available_modes.join(" / ")}${seedNote}`
    : "No challenge selected.";

  for (const value of ["live", "live_adaptive", "live_multiagent"]) {
    const option = element("mode").querySelector(`option[value="${value}"]`);
    option.disabled = !scenario?.available_modes.includes(value);
  }
  if (!scenario?.available_modes.includes(element("mode").value)) element("mode").value = "replay";
  const unifiedProfiles = new Set([
    "allowlist_only", "content_only", "actor_local", "transitive",
    "scoped_release", "strict_no_release",
  ]);
  for (const option of element("defense").options) {
    option.disabled = unified ? !unifiedProfiles.has(option.value) : unifiedProfiles.has(option.value);
  }
  if (element("defense").selectedOptions[0]?.disabled) {
    element("defense").value = unified ? "transitive" : "taint";
  }
  const mode = element("mode").value;
  const arm = element("adaptive-arm");
  arm.querySelector('option[value="A5"]').disabled = number !== 28;
  arm.querySelector('option[value="A1"]').disabled = adaptive && mode === "live_adaptive";
  for (const value of ["A2", "A4"]) {
    arm.querySelector(`option[value="${value}"]`).disabled = adaptive && mode !== "live_adaptive";
  }
  if (arm.selectedOptions[0]?.disabled) arm.value = mode === "live_adaptive" ? "A3" : "A1";

  element("model-field").hidden = !(mode === "live" || mode === "live_multiagent" ||
    (mode === "live_adaptive" && adaptive));
  element("extension-fields").hidden = !extension;
  element("adaptive-fields").hidden = !adaptive;
  element("attack-row").hidden = extension || adaptive;
  const transfer = adaptive && number === 28 && arm.value === "A5";
  element("adaptive-reviewer").disabled = transfer;
  if (transfer) element("adaptive-reviewer").value = "metadata_schema";
  element("transfer-field").hidden = !transfer;
  element("adaptive-split").disabled = !transfer;
  if (!transfer) element("adaptive-split").value = "development";
}

export function renderRecentRuns(runs, activeRunId, onChoose) {
  const list = element("recent-runs");
  if (!runs.length) {
    const empty = document.createElement("p");
    empty.className = "muted small";
    empty.textContent = "No runs yet. Start your first experiment.";
    list.replaceChildren(empty);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const run of runs) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `recent-run ${run.run_id === activeRunId ? "active" : ""}`;
    const dot = document.createElement("span");
    dot.className = `run-dot ${run.status}`;
    const copy = document.createElement("span");
    const title = document.createElement("span");
    title.className = "run-short";
    title.textContent = `${run.scenario_id} · ${run.defense_profile}`;
    const sub = document.createElement("span");
    sub.className = "run-sub";
    sub.textContent = `${run.mode.toUpperCase()}  /  ${run.status}`;
    copy.append(title, sub);
    const arrow = document.createElement("span");
    arrow.className = "run-arrow";
    arrow.textContent = "›";
    button.append(dot, copy, arrow);
    button.title = run.run_id;
    button.addEventListener("click", () => onChoose(run.run_id));
    fragment.append(button);
  }
  list.replaceChildren(fragment);
}

export function renderRun(status, report, events) {
  const pill = element("run-state");
  pill.className = `status-pill ${status?.status || "idle"}`;
  pill.textContent = status ? status.status.replaceAll("_", " ") : "No run selected";
  element("run-identity").textContent = status ? status.run_id : "Choose a challenge to begin";
  element("run-identity").title = status?.run_id || "";
  element("run-meta").textContent = status
    ? `${status.scenario_id} / ${status.mode.toUpperCase()} / ${status.defense_profile}${status.arm ? ` / ${status.arm}` : ""}${status.observer_profile ? ` / ${status.observer_profile}` : ""}${status.model_name ? ` / ${status.model_name}` : ""}`
    : "Replay is ready without a model.";
  element("cancel-run").hidden = !status || terminal.has(status.status);

  const security = element("security-value");
  const securityCard = security.closest(".metric-card");
  const utility = element("utility-value");
  const utilityCard = utility.closest(".metric-card");
  const score = report || status || {};
  const shown = scorePresentation(status, report);
  security.textContent = shown.security;
  utility.textContent = shown.utility;
  element("security-detail").textContent = shown.detail;
  element("utility-detail").textContent = shown.utilityDetail;
  securityCard.classList.toggle("alert", shown.securityAlert);
  utilityCard.classList.toggle("alert", shown.utilityAlert);
  element("accepted-count").textContent = measuredNumber(scoreField(score, "accepted_sink_receipts", "accepted_outbound_events"));
  element("blocked-count").textContent = measuredNumber(scoreField(score, "all_run_blocks", "blocked_attempts"));
  element("scoring-details").hidden = !status;
  element("score-version").textContent = score.scoring_version || "Not measured";
  element("oracle-validation").textContent = score.oracle_validation || "unknown";
  element("observer-coverage").textContent = shown.observer;
  element("strict-win").textContent = shown.strictWin;
  element("score-eligibility").textContent = `${measuredBoolean(score.strict_trial_eligible)}${score.eligibility_reasons?.length ? ` · ${score.eligibility_reasons.join(", ")}` : ""}`;
  element("all-alerts").textContent = measuredNumber(score.all_run_alerts);
  element("utility-details").hidden = !status;
  const utilityVersions = new Set(["legacy-safe-writer-v1", "sensitive-utility-v2", "sensitive-utility-v3",
    "extension-utility-v2", "adaptive-utility-v2", "unified-utility-v2"]);
  element("utility-version").textContent = utilityVersions.has(score.utility_version) ? score.utility_version : "Unknown";
  element("utility-scope").textContent = ({
    legacy_safe_writer: "Separate safe writer",
    same_reader_scripted: "Classified reader · scripted task",
    same_reader_model_decision: "Classified reader · model decision",
  })[score.utility_scope] || "Unknown";
  element("task-mechanism").textContent = ({
    scripted_computation: "Scripted computation", model_computation: "Model computation",
    trusted_formatter: "Trusted formatter",
  })[score.task_mechanism] || "Unknown";
  const taskActors = new Set(["operations_worker", "customer_worker", "response_writer",
    ...Array.from({length: 10}, (_, index) => `A${index}`)]);
  element("task-actor").textContent = taskActors.has(score.task_actor) ? score.task_actor : "Unknown";
  element("independent-mode-note").hidden = status?.mode !== "live_multiagent";
  element("task-model-calls").textContent = measuredNumber(score.task_model_calls);
  const completedUtility = (status?.status || score.status) === "completed";
  const sameReader = completedUtility && score.utility_scope !== "legacy_safe_writer";
  element("same-reader-utility").textContent = measuredBoolean(sameReader ? score.same_reader_utility : null);
  element("task-contribution").textContent = measuredBoolean(sameReader ? score.contribution_verified : null);
  element("task-sequence").textContent = measuredBoolean(completedUtility ? score.customer_sequence_consistent : null);
  element("task-required-actions").textContent = `${measuredNumber(score.accepted_required_count)} / ${measuredNumber(score.required_action_count)}`;
  element("benign-cost-details").hidden = !status;
  const cost = benignCostPresentation(score.benign_cost);
  element("information-details").hidden = !status;
  const info = informationPresentation(score.information);
  for (const [name, value] of Object.entries(info)) element(`information-${name}`).textContent = value;
  element("benign-eligible").textContent = cost.eligible;
  element("benign-false-alerts").textContent = cost.alerts;
  element("benign-false-blocks").textContent = cost.blocks;
  element("benign-alert-runs").textContent = cost.alertRuns;
  element("benign-block-runs").textContent = cost.blockRuns;
  element("benign-matched-shapes").textContent = cost.shapes;
  element("knowledge-details").hidden = !status;
  element("fixture-mode").textContent = ({
    key_derived_unknown: "Key derived target",
    public_transport_control: "Public transport control",
  })[score.fixture_mode] || "Unknown";
  element("fixture-mode").title = score.fixture_derivation_version || "Unknown derivation";
  element("policy-knowledge").textContent = ({
    privileged_known_secret: "Privileged expected marker",
    authenticated_source_content: "Authorized source content",
    no_content_inspection: "No content inspection",
    runtime_provenance: "Runtime provenance",
  })[score.policy_knowledge] || "Unknown";
  element("policy-knowledge").title = score.policy_known_target || "Unknown target access";
  element("observer-knowledge").textContent = ({
    disabled: "Disabled",
    "keyless-proposal-content-v1": "Keyless proposal content",
    "keyless-proposal-metadata-v1": "Keyless proposal metadata",
    "keyless-runtime-labels-v1": "Keyless runtime labels",
  })[score.observer_knowledge] || "Unknown";
  const receiver = ({
    sealed_aead_key_and_issued_fixture: "Private AEAD key and issued fixture",
    public_control_aead_key_and_issued_fixture: "Public control key and issued fixture",
    public_decoder_conventions: "Public decoder conventions",
    public_finite_codebook: "Public finite codebook",
    public_decoder_and_issued_attack_id: "Public decoder and issued artifact ID",
  })[score.receiver_knowledge];
  const comparison = ({
    sealed_expected_target: "sealed expected target",
    public_control_expected_target: "public control target",
  })[score.receiver_target_comparison];
  element("receiver-knowledge").textContent = receiver
    ? `${receiver}${comparison ? ` · ${comparison}` : ""}` : "Unknown";
  element("execution-details").hidden = !status;
  element("decision-count").textContent = `${measuredNumber(score.decision_turns)} / ${measuredNumber(score.max_decision_turns)}`;
  element("model-request-count").textContent = `${measuredNumber(score.total_model_calls)} / ${measuredNumber(score.max_total_model_calls)}`;
  element("script-turn-count").textContent = measuredNumber(score.scripted_turns);
  element("decision-accounting").textContent = ({
    fixed_script_activations: "Fixed script activations",
    model_request_attempts: "Model request attempts",
    script_and_model_attempts: "Scripts and model requests",
  })[score.decision_accounting] || "Not measured";
  const extension = score.arm != null;
  element("extension-details").hidden = !extension;
  if (extension) {
    element("verified-bits").textContent = measuredNumber(score.verified_bits);
    element("alert-split").textContent = `${measuredNumber(score.attack_alerts)} / ${measuredNumber(score.benign_alerts)}`;
    element("undetected-success").textContent = shown.strictWin;
  }
  const adaptive = score.rounds_used != null;
  element("adaptive-details").hidden = !adaptive;
  if (adaptive) {
    element("adaptive-round-count").textContent = `${measuredNumber(score.rounds_used)} / ${measuredNumber(score.round_limit)}`;
    element("adaptive-candidate-count").textContent = `${measuredNumber(score.valid_candidates)} / ${measuredNumber(score.invalid_candidates)}`;
    element("adaptive-call-count").textContent = `${measuredNumber(score.attacker_model_calls)} / ${measuredNumber(score.gateway_calls)}`;
    element("adaptive-stop-reason").textContent = score.stop_reason || "—";
    element("adaptive-alert-count").textContent = measuredNumber(scoreField(score, "all_run_alerts", "alerts"));
    element("adaptive-novelty").textContent = score.novelty_status || "unassessed";
  }
  const unified = /^unified-v/.test(score.scenario_revision || "") || score.report_contract_version === "unified-v2";
  element("unified-details").hidden = !unified;
  if (unified) {
    element("unified-recovery").textContent = `${measuredBoolean(shown.full)} / ${measuredBoolean(scoreField(score, "accepted_egress", "accepted_external_artifact"))}`;
    element("unified-alert").textContent = `${measuredNumber(score.pre_egress_alerts)} / ${measuredNumber(score.post_egress_alerts)}`;
    element("unified-lineage").textContent = `${measuredNumber(score.lineage_gap_count)} / ${measuredNumber(score.lineage_unknown_count)}`;
    element("unified-flow").textContent = `${measuredNumber(score.peer_deliveries)} / ${measuredNumber(score.blocked_egress_attempts)}`;
    element("unified-win").textContent = shown.strictWin;
  }
  const sensitive = score.partial_information_score != null;
  element("sensitive-details").hidden = !sensitive;
  if (sensitive) {
    element("partial-score").textContent = Number(score.partial_information_score).toFixed(2);
    element("alert-count").textContent = measuredNumber(scoreField(score, "all_run_alerts", "alerts"));
    element("legitimate-block-count").textContent = measuredNumber(score.legitimate_actions_blocked);
  }
}

const lifecycleNames = {
  "run.started": "Run started", "run.completed": "Run completed",
  "run.failed": "Run failed", "run.cancelled": "Run cancelled",
  "run.timed_out": "Run timed out", "agent.message": "Agent handoff",
};

export function renderTimeline(events) {
  element("event-count").textContent = String(events.length);
  const container = element("timeline");
  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "empty-timeline";
    const title = document.createElement("strong");
    title.textContent = "No events yet";
    const detail = document.createElement("p");
    detail.textContent = "Start a run or open one from the sidebar to inspect policy decisions.";
    empty.append(title, detail);
    container.replaceChildren(empty);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const event of events) {
    const data = event.data || {};
    const row = document.createElement("article");
    row.className = `event-row ${data.policy_decision === "block" ? "block" : ["run.failed", "run.timed_out"].includes(event.event) ? "fail" : ""}`;
    const index = document.createElement("span");
    index.className = "event-index";
    index.textContent = String(event.id).padStart(2, "0");
    const content = document.createElement("div");
    const title = document.createElement("div");
    title.className = "event-title";
    const name = document.createElement("span");
    name.textContent = event.event === "tool.proposed" ? data.tool_name || "Tool proposal" : lifecycleNames[event.event] || event.event;
    title.append(name);
    if (["allow", "block"].includes(data.policy_decision)) {
      const decision = document.createElement("span");
      decision.className = "event-decision";
      decision.textContent = data.policy_decision;
      title.append(decision);
    }
    if (data.summary?.observer_alert === true) {
      const alert = document.createElement("span");
      alert.className = "event-decision observer-alert";
      alert.textContent = `observer alert · ${{before_receipt: "before receipt", after_receipt: "after receipt"}[data.summary.observer_phase] || "timing unknown"}`;
      title.append(alert);
    }
    const meta = document.createElement("div");
    meta.className = "event-meta";
    const details = [data.actor_id, data.destination ? `→ ${data.destination}` : null, data.reason_code && data.reason_code !== "allowed" ? data.reason_code : null, data.summary?.observer_alert ? data.summary.observer_reason : null, data.data_class].filter(Boolean);
    meta.textContent = details.join("  ·  ");
    content.append(title, meta);
    if (data.payload_sha256) {
      const digest = document.createElement("div");
      digest.className = "event-meta event-digest";
      digest.textContent = `sha256 ${data.payload_sha256.slice(0, 16)}…`;
      content.append(digest);
    }
    row.append(index, content);
    fragment.append(row);
  }
  container.replaceChildren(fragment);
}
