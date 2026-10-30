// Local playback controller. SSE supplies data; animation never polls the server.
import {buildTrace, stateAt, callTemplate} from './flow-model.js';
import {drawGraph} from './flow-graph.js';
const $ = (id) => document.getElementById(id);

export class FlowPlayer {
  constructor() {
    this.trace = buildTrace([], null, null, null);
    this.index = 0;
    this.playing = false;
    this.animation = null;
    this.speed = 1;
    this.runId = null;
    this.reduced = matchMedia('(prefers-reduced-motion: reduce)');
    this.idle = null;
    $('flow-play').addEventListener('click', () => this.playing ? this.pause() : this.play());
    $('flow-back').addEventListener('click', () => this.seek(this.index - 1));
    $('flow-next').addEventListener('click', () => this.seek(this.index + 1));
    $('flow-restart').addEventListener('click', () => this.seek(0));
    $('flow-end').addEventListener('click', () => this.seek(this.trace.frames.length - 1));
    $('flow-attack').addEventListener('click', () => {
      const i = this.trace.frames.findIndex((f) => f.phase === 'attack');
      if (i >= 0) this.seek(i);
    });
    $('flow-speed').addEventListener('change', (event) => {
      this.speed = Number(event.target.value);
      if (this.animation) this.animation.playbackRate = this.speed;
    });
    $('flow-scrub').addEventListener('input', (event) => this.seek(Number(event.target.value)));
    $('flow-frame-list').addEventListener('change', (event) => this.seek(Number(event.target.value)));
    document.addEventListener('visibilitychange', () => {if (document.hidden) this.pause();});
    this.reduced.addEventListener('change', () => {this.pause(); this.render();});
    for (const name of ['pointerdown', 'keydown']) $('flow-theater').addEventListener(name, () => this.touch());
  }

  touch() {
    clearTimeout(this.idle);
    if (this.playing) this.idle = setTimeout(() => this.pause('Playback paused after 5 minutes of inactivity.'), 300_000);
  }

  update(scenario, status, report, events) {
    const key = status?.run_id || `preview:${scenario?.id}`;
    const next = buildTrace(events, scenario, status, report);
    const changed = key !== this.runId;
    const oldFrame = this.trace.frames[this.index]?.key;
    const oldLength = this.trace.frames.length;
    this.trace = next;
    if (changed) {
      this.pause(); this.index = 0; this.runId = key;
    } else if (oldFrame) {
      const found = next.frames.findIndex((f) => f.key === oldFrame);
      this.index = found < 0 ? 0 : found;
    }
    const list = $('flow-frame-list');
    if (changed || oldLength !== next.frames.length) {
      list.replaceChildren(...next.frames.map((frame, i) => {
        const option = document.createElement('option');
        option.value = String(i); option.textContent = `${i + 1}. #${frame.eventId} · ${frame.title}`;
        return option;
      }));
    }
    if (changed || !this.animation || !this.playing) this.render();
    else this.renderCounters();
  }

  seek(index) {
    this.pause();
    this.index = Math.max(0, Math.min(index, this.trace.frames.length - 1));
    this.render();
  }

  play() {
    if (!this.trace.frames.length) return;
    if (this.index >= this.trace.frames.length - 1) {this.index = 0; this.render();}
    this.playing = true;
    this.animation?.play();
    this.touch(); this.renderCounters();
  }

  pause(message = '') {
    this.playing = false;
    this.animation?.pause();
    clearTimeout(this.idle);
    if (message) $('flow-evidence').textContent = message;
    this.renderCounters();
  }

  renderCounters() {
    const count = this.trace.frames.length;
    $('flow-play').textContent = this.playing ? 'Pause' : 'Play trace';
    $('flow-play').disabled = !count;
    $('flow-back').disabled = !count || this.index === 0;
    $('flow-next').disabled = !count || this.index >= count - 1;
    $('flow-restart').disabled = !count;
    $('flow-end').disabled = !count;
    $('flow-attack').disabled = !this.trace.frames.some((f) => f.phase === 'attack');
    $('flow-scrub').max = String(Math.max(0, count - 1));
    $('flow-scrub').value = String(this.index);
    $('flow-scrub').disabled = !count;
    $('flow-step').textContent = count ? `${this.index + 1} / ${count} steps` : 'Waiting for a run';
    $('flow-frame-list').value = String(this.index);
  }

  inspectNode(node) {
    this.pause();
    $('flow-event-title').textContent = `${node.id} · ${node.role.replaceAll('_', ' ')}`;
    const relevant = this.trace.frames.filter((f) => f.from === node.id || f.to === node.id);
    $('flow-event-detail').textContent = relevant.length ? `${relevant.length} visual steps involve this node. Use the event selector to inspect the recorded boundaries.` : 'No boundary event is recorded for this role. Its presence in the roster does not imply a message was sent.';
  }

  render() {
    this.animation?.cancel();
    const frame = this.trace.frames[this.index];
    const scenario = this.trace.scenario;
    this.animation = drawGraph($('flow-canvas'), this.trace, this.index, (node) => this.inspectNode(node), this.reduced.matches);
    this.animation.pause(); this.animation.playbackRate = this.speed;
    if (!this.playing) this.animation.currentTime = 1500;
    this.animation.onfinish = () => {
      if (!this.playing) return;
      if (this.index < this.trace.frames.length - 1) {
        this.index += 1; this.render();
      } else {this.pause(); this.render();}
    };
    if (this.playing) this.animation.play();
    const mechanism = frame ? frame.mechanism : this.trace.independent ? null : scenario?.visualization?.mechanisms[0];
    $('flow-scenario').textContent = scenario ? `${scenario.id} · ${scenario.title}` : 'Select an experiment';
    $('flow-event-title').textContent = frame?.title || 'A trace you can follow';
    $('flow-event-detail').textContent = frame?.detail || 'Open a run, then press Play trace. The same player works across all registered scenarios.';
    $('flow-phase').textContent = frame ? `EVENT #${frame.eventId} · ${frame.phase.toUpperCase()}` : 'EVENT-DRIVEN PLAYBACK';
    $('flow-mechanism-title').textContent = mechanism?.title || (this.trace.independent ? 'Representation not recorded' : 'Scenario mechanism');
    $('flow-formula').textContent = mechanism?.formula || (this.trace.independent ? 'Not measured' : 'S → f(S) → outbound field');
    $('flow-explanation').textContent = mechanism?.explanation || (this.trace.independent ? 'An assigned role or allowed route does not establish which representation the model chose.' : 'The explanation will follow the selected scenario.');
    const shape = frame?.event.data?.summary?.visual;
    $('flow-operation').textContent = shape?.operators ? `Recorded operators: ${shape.operators.join(' → ') || 'identity'}` : shape?.style ? `Recorded layout: ${shape.style}` : `Implementation: ${mechanism?.implementation || 'not selected'}`;
    $('flow-call').textContent = callTemplate(frame);
    $('flow-evidence').textContent = frame
      ? `${shape?.representation ? 'Runtime representation metadata available.' : this.trace.independent ? 'No representation is inferred from the replay scenario.' : 'This event has no representation metadata; the mechanism is scenario context.'} Formula and call values are symbolic; this is not a raw payload viewer.`
      : scenario?.visualization?.note || '';
    const state = stateAt(this.trace, this.index);
    $('flow-admin').textContent = state.observer;
    $('flow-admin').classList.toggle('is-alert', state.alerts > 0);
    $('flow-policy').textContent = `${state.accepted} accepted · ${state.blocked} blocked`;
    $('flow-oracle').textContent = state.verdict;
    $('flow-oracle').classList.toggle('is-alert', state.securityAlert);
    $('flow-result-note').textContent = state.resultNote;
    $('flow-motion-note').textContent = this.reduced.matches ? 'Reduced motion · step changes remain available' : 'Illustrative timing · recorded event order';
    this.renderCounters();
  }
}
