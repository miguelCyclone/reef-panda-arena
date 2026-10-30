// Browser acceptance check using Chrome's local DevTools protocol; no npm dependency.
// Run check_visualization.py first, serve on 8001, and start headless Chrome on 9223.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const base = process.env.ARENA_VISUAL_URL || 'http://127.0.0.1:8001';
const devtools = process.env.ARENA_DEVTOOLS_URL || 'http://127.0.0.1:9223';
const targets = await (await fetch(`${devtools}/json/list`)).json();
const page = targets.find((target) => target.type === 'page');
assert.ok(page, 'Chrome needs an open page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve) => ws.addEventListener('open', resolve, {once: true}));
let serial = 0;
const pending = new Map();
const errors = [];
ws.addEventListener('message', (event) => {
  const message = JSON.parse(event.data);
  if (message.id) {
    const request = pending.get(message.id);
    pending.delete(message.id);
    clearTimeout(request.timeout);
    if (message.error) request.reject(message.error); else request.resolve(message.result);
  }
  if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
});
function cdp(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++serial;
    const timeout = setTimeout(() => reject(new Error(`Timed out: ${method}`)), 30000);
    pending.set(id, {resolve, reject, timeout});
    ws.send(JSON.stringify({id, method, params}));
  });
}
async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
  if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function load(trace) {
  await cdp('Page.navigate', {url: `${base}/library?run=${trace.status.run_id}`});
  await evaluate(`new Promise((resolve, reject) => {
    const ready = () => document.querySelector('#run-identity')?.textContent === ${JSON.stringify(trace.status.run_id)} && document.querySelector('#flow-frame-list')?.options.length > 1;
    if (ready()) return resolve(true);
    const observer = new MutationObserver(() => {if (ready()) {observer.disconnect(); clearTimeout(timer); resolve(true);}});
    observer.observe(document, {childList: true, subtree: true});
    const timer = setTimeout(() => {observer.disconnect(); reject(Error('Trace load timeout'));}, 10000);
  })`);
}
async function click(id) {await evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);}
async function screenshot(name) {
  const result = await cdp('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
  await fs.writeFile(`.build/visualization/${name}.png`, Buffer.from(result.data, 'base64'));
}
try {
  await cdp('Page.enable'); await cdp('Runtime.enable');
  await cdp('Emulation.setEmulatedMedia', {features: [{name: 'prefers-reduced-motion', value: 'no-preference'}]});
  await cdp('Emulation.setDeviceMetricsOverride', {width: 1600, height: 1150, deviceScaleFactor: 1, mobile: false});
  const traces = JSON.parse(await fs.readFile('.build/visualization/traces.json', 'utf8'));
  const numeric = traces.find((t) => t.status.scenario_id === 'C32' && t.status.defense_profile === 'allowlist_only');
  await load(numeric);
  const coverage = await evaluate(`(async () => {
    const {buildTrace, stateAt} = await import('/assets/flow-model.js');
    const {drawGraph} = await import('/assets/flow-graph.js');
    const traces = ${JSON.stringify(traces)};
    const holder = document.createElement('div'); document.body.append(holder);
    let frameCount = 0;
    try {
      for (const source of traces) {
        const trace = buildTrace(source.events, source.scenario, source.status, source.report);
        const result = stateAt(trace, trace.frames.length - 1);
        if (result.accepted !== source.report.accepted_outbound_events) throw Error('Sink count mismatch: ' + source.status.scenario_id);
        if (source.report.alerts != null && result.alerts !== source.report.alerts) throw Error('Observer count mismatch: ' + source.status.scenario_id);
        for (const event of source.events) if (!trace.frames.some(f => f.eventId === event.id)) throw Error('Dropped event');
        for (let i = 0; i < trace.frames.length; i++) {
          const animation = drawGraph(holder, trace, i, () => {}, true);
          animation.cancel(); frameCount++;
          if (i === trace.frames.length - 1) {
            const expected = (source.status.attack_enabled ?? source.report.attacker_attempted) === false ? 0 : (source.report.compromised_roles || source.scenario.visualization.compromised_roles).length;
            if (holder.querySelectorAll(".flow-node.rogue").length !== expected) throw Error("Compromised role mismatch");
          }
        }
      }
    } finally {holder.remove();}
    return {traces: traces.length, scenarios: new Set(traces.map(t => t.status.scenario_id)).size, frames: frameCount};
  })()`);
  assert.equal(coverage.scenarios, 44);
  console.log('Full catalog render:', coverage);
  await click('flow-attack');
  assert.equal(await evaluate(`document.getElementById('flow-canvas').getAnimations({subtree:true}).some(a => a.effect.getKeyframes().some(f => f.transform))`), true, 'Normal motion includes a traveling packet');
  const before = await evaluate(`Number(document.getElementById('flow-scrub').value)`);
  await click('flow-play');
  await evaluate('new Promise(resolve => setTimeout(resolve, 1750))');
  await click('flow-play');
  const after = await evaluate(`Number(document.getElementById('flow-scrub').value)`);
  assert.ok(after > before, 'Playback advances');
  const paused = await evaluate(`document.getElementById('flow-scrub').value`);
  await evaluate('new Promise(resolve => setTimeout(resolve, 1700))');
  assert.equal(await evaluate(`document.getElementById('flow-scrub').value`), paused, 'Pause holds');
  await evaluate(`(() => {const list=document.getElementById('flow-frame-list'); list.value=[...list.options].find(o=>o.textContent.includes('Agent changes')).value; list.dispatchEvent(new Event('change')); document.getElementById('flow-theater').scrollIntoView({behavior:'instant', block:'start'});})()`);
  await screenshot('trace-studio-desktop');
  await click('flow-end');
  assert.match(await evaluate(`document.getElementById('flow-oracle').textContent`), /Secret recovered/);
  assert.match(await evaluate(`document.getElementById('flow-admin').textContent`), /No alert/);
  for (const [sid, defense] of [['C03','none'], ['C03','taint'], ['C32','transitive'], ['C18','none'], ['C24','none'], ['C40','actor_local']]) {
    const trace=traces.find(t=>t.status.scenario_id===sid && t.status.defense_profile===defense);
    await load(trace); await click('flow-end');
    const verdict=await evaluate(`document.getElementById('flow-oracle').textContent`);
    assert.equal(verdict.includes('Secret recovered'), Boolean(trace.report.secret_escaped), sid);
    console.log(`${sid} / ${defense}: ${verdict}`);
  }
  const benign=traces.find(t=>t.status.scenario_id==='C00' && !t.report.attacker_attempted);
  await load(benign);
  assert.equal(await evaluate(`document.querySelectorAll('.flow-node.rogue').length`), 0, 'Benign control has no compromised actor');
  await load(numeric);
  await cdp('Emulation.setEmulatedMedia', {features: [{name: 'prefers-reduced-motion', value: 'reduce'}]});
  await click('flow-attack'); await click('flow-play');
  assert.equal(await evaluate(`document.getElementById('flow-canvas').getAnimations({subtree:true}).some(a => a.effect.getKeyframes().some(f => f.transform))`), false, 'Reduced motion removes traveling packets');
  await click('flow-play');
  await cdp('Emulation.setDeviceMetricsOverride', {width: 390, height: 900, deviceScaleFactor: 1, mobile: true});
  await evaluate(`document.getElementById('flow-theater').scrollIntoView({behavior:'instant', block:'start'})`);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), true, 'No mobile page overflow');
  await screenshot('trace-studio-mobile');
  assert.deepEqual(errors, [], 'No browser exceptions');
  console.log('Playback, pause, evidence, benign control, reduced motion and mobile layout passed');
} finally {
  ws.close();
}
