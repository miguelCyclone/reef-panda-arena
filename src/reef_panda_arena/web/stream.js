// One SSE subscription at a time, with explicit recovery and a user-idle cutoff.

const EVENT_TYPES = ["run.started", "tool.proposed", "agent.message", "run.completed", "run.failed", "run.cancelled", "run.timed_out"];
const TERMINAL_TYPES = new Set(["run.completed", "run.failed", "run.cancelled", "run.timed_out"]);
const RETRY_MS = 30_000;
const IDLE_MS = 300_000;

export class RunStream {
  constructor({ onRecover, onEvent, onState, clock = () => Date.now(), schedule = (callback, delay) => window.setTimeout(callback, delay), cancel = (timer) => window.clearTimeout(timer), eventSource = (url) => new EventSource(url) }) {
    this.onRecover = onRecover;
    this.onEvent = onEvent;
    this.onState = onState;
    this.clock = clock;
    this.schedule = schedule;
    this.cancel = cancel;
    this.eventSource = eventSource;
    this.runId = null;
    this.source = null;
    this.retryTimer = null;
    this.idleTimer = null;
    this.lastInteraction = 0;
    this.generation = 0;
  }

  connect(runId) {
    this.stop();
    this.runId = runId;
    this.lastInteraction = this.clock();
    this._armIdle();
    void this._open(this.generation);
  }

  touch() {
    if (!this.runId) return;
    this.lastInteraction = this.clock();
    this._armIdle();
  }

  resume() {
    if (!this.runId) return;
    this.touch();
    this._closeTransport();
    this.generation += 1;
    void this._open(this.generation);
  }

  stop() {
    this.generation += 1;
    this._closeTransport();
    if (this.idleTimer !== null) this.cancel(this.idleTimer);
    this.idleTimer = null;
    this.runId = null;
  }

  _closeTransport() {
    if (this.source) this.source.close();
    this.source = null;
    if (this.retryTimer !== null) this.cancel(this.retryTimer);
    this.retryTimer = null;
  }

  _armIdle() {
    if (this.idleTimer !== null) this.cancel(this.idleTimer);
    const remaining = Math.max(0, IDLE_MS - (this.clock() - this.lastInteraction));
    this.idleTimer = this.schedule(() => this._pause(), remaining);
  }

  _pause() {
    this.generation += 1;
    this._closeTransport();
    this.onState("paused");
  }

  async _open(generation) {
    if (!this.runId || generation !== this.generation) return;
    if (this.clock() - this.lastInteraction >= IDLE_MS) {
      this._pause();
      return;
    }
    this.onState("connecting");
    const runId = this.runId;
    try {
      const active = await this.onRecover(runId);
      if (generation !== this.generation || runId !== this.runId) return;
      if (!active) {
        this.stop();
        this.onState("complete");
        return;
      }
    } catch (error) {
      if (generation !== this.generation) return;
      if (error.status === 404) {
        this.stop();
        this.onState("error");
      } else {
        this._retry(generation);
      }
      return;
    }
    if (this.clock() - this.lastInteraction >= IDLE_MS) {
      this._pause();
      return;
    }
    const source = this.eventSource(`/v1/runs/${encodeURIComponent(runId)}/stream`);
    this.source = source;
    source.onopen = () => {
      if (source === this.source) this.onState("live");
    };
    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (message) => {
        if (source !== this.source) return;
        try {
          this.onEvent({ id: Number(message.lastEventId), event: type, data: JSON.parse(message.data) });
        } catch {
          this.onState("error");
          return;
        }
        if (TERMINAL_TYPES.has(type)) {
          this.stop();
          this.onState("complete");
        }
      });
    }
    source.onerror = () => {
      if (source !== this.source) return;
      this._closeTransport();
      this._retry(generation);
    };
  }

  _retry(generation) {
    if (this.clock() - this.lastInteraction >= IDLE_MS) {
      this._pause();
      return;
    }
    this.onState("retrying");
    this.retryTimer = this.schedule(() => {
      this.retryTimer = null;
      void this._open(generation);
    }, RETRY_MS);
  }
}
