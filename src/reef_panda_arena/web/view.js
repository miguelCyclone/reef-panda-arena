// Render only sanitized API fields with text nodes.

const element = (id) => document.getElementById(id);
const terminal = new Set(["completed", "failed", "cancelled", "timed_out"]);

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
  element("scenario-detail").textContent = scenario
    ? `Level ${scenario.difficulty} · ${scenario.channel} · ${scenario.available_modes.join(" / ")}`
    : "No challenge selected.";
  const live = element("mode").querySelector('option[value="live"]');
  live.disabled = !scenario?.available_modes.includes("live");
  if (live.disabled && element("mode").value === "live") element("mode").value = "replay";
  element("model-field").hidden = element("mode").value !== "live";
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
    ? `${status.scenario_id} / ${status.mode.toUpperCase()} / ${status.defense_profile}${status.model_name ? ` / ${status.model_name}` : ""}`
    : "Replay is ready without a model.";
  element("cancel-run").hidden = !status || terminal.has(status.status);

  const security = element("security-value");
  const securityCard = security.closest(".metric-card");
  const utility = element("utility-value");
  const utilityCard = utility.closest(".metric-card");
  securityCard.classList.remove("alert");
  utilityCard.classList.remove("alert");
  if (!status) {
    security.textContent = "Awaiting run";
    utility.textContent = "Awaiting run";
    element("security-detail").textContent = "Exact accepted-egress verdict";
    element("utility-detail").textContent = "Cause, ETA and safe update";
  } else if (status.status !== "completed" || !report) {
    const label = terminal.has(status.status) ? "Not scored" : "In progress";
    security.textContent = label;
    utility.textContent = label;
    element("security-detail").textContent = status.failure_code || "Waiting for exact oracle verdict";
    element("utility-detail").textContent = status.failure_code || "Waiting for customer update";
  } else {
    security.textContent = !report.attacker_attempted ? "No attack" : report.secret_escaped ? "Secret escaped" : "Contained";
    element("security-detail").textContent = !report.attacker_attempted ? "Matched benign control" : report.secret_escaped ? "Exact secret reached local sink" : "No exact secret in accepted egress";
    if (report.secret_escaped) securityCard.classList.add("alert");
    utility.textContent = report.benign_task_success ? "Task complete" : "Task failed";
    element("utility-detail").textContent = report.benign_task_success ? "Safe customer update delivered" : "Customer task rubric not met";
    if (!report.benign_task_success) utilityCard.classList.add("alert");
  }
  element("accepted-count").textContent = status?.accepted_outbound_events ?? "—";
  element("blocked-count").textContent = status ? (report?.blocked_attempts ?? events.filter((item) => item.data?.policy_decision === "block").length) : "—";
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
    const meta = document.createElement("div");
    meta.className = "event-meta";
    const details = [data.actor_id, data.destination ? `→ ${data.destination}` : null, data.reason_code && data.reason_code !== "allowed" ? data.reason_code : null, data.data_class].filter(Boolean);
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
