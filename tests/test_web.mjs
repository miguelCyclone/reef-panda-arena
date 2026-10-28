import assert from "node:assert/strict";
import test from "node:test";
import { RunStream } from "../src/reef_panda_arena/web/stream.js";

class FakeTimers {
  constructor() { this.now = 0; this.nextId = 1; this.tasks = new Map(); }
  schedule = (callback, delay) => {
    const id = this.nextId++;
    this.tasks.set(id, { at: this.now + delay, callback });
    return id;
  };
  cancel = (id) => this.tasks.delete(id);
  advance(amount) {
    this.now += amount;
    for (const [id, task] of [...this.tasks]) {
      if (task.at <= this.now) {
        this.tasks.delete(id);
        task.callback();
      }
    }
  }
}

class FakeEventSource {
  constructor(url) { this.url = url; this.closed = false; this.listeners = new Map(); }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  close() { this.closed = true; }
  emit(type, id) { this.listeners.get(type)({ lastEventId: String(id), data: "{}" }); }
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test("SSE retries after 30 seconds, refreshes history, and stops at 300 seconds idle", async () => {
  const timers = new FakeTimers();
  const sources = [];
  const states = [];
  let recoveries = 0;
  const stream = new RunStream({
    clock: () => timers.now, schedule: timers.schedule, cancel: timers.cancel,
    eventSource: (url) => { const source = new FakeEventSource(url); sources.push(source); return source; },
    onRecover: async () => { recoveries += 1; return true; },
    onEvent: () => {}, onState: (state) => states.push(state),
  });
  stream.connect("run-id");
  await flush();
  assert.equal(recoveries, 1);
  assert.equal(sources.length, 1);
  sources[0].onerror();
  assert.equal(sources[0].closed, true);
  assert.equal(states.at(-1), "retrying");
  timers.advance(29_999);
  await flush();
  assert.equal(recoveries, 1);
  timers.advance(1);
  await flush();
  assert.equal(recoveries, 2);
  assert.equal(sources.length, 2);
  timers.advance(270_000);
  assert.equal(states.at(-1), "paused");
  assert.equal(sources[1].closed, true);
  assert.equal(timers.tasks.size, 0);
  stream.stop();
});

test("terminal event closes the source and cancels the idle timer", async () => {
  const timers = new FakeTimers();
  const sources = [];
  const events = [];
  const stream = new RunStream({
    clock: () => timers.now, schedule: timers.schedule, cancel: timers.cancel,
    eventSource: (url) => { const source = new FakeEventSource(url); sources.push(source); return source; },
    onRecover: async () => true, onEvent: (event) => events.push(event), onState: () => {},
  });
  stream.connect("run-id");
  await flush();
  sources[0].emit("run.completed", 9);
  assert.deepEqual(events.map((event) => event.id), [9]);
  assert.equal(sources[0].closed, true);
  assert.equal(timers.tasks.size, 0);
  assert.equal(stream.runId, null);
});
