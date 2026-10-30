// Event-driven local Chrome acceptance; no polling, account access or external page.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const base=process.env.ARENA_BOOKING_URL||'http://127.0.0.1:8003';
const devtools=process.env.ARENA_BOOKING_DEVTOOLS||'http://127.0.0.1:9224';
const targets=await (await fetch(`${devtools}/json/list`)).json();
const page=targets.find(item=>item.type==='page');assert.ok(page);
const ws=new WebSocket(page.webSocketDebuggerUrl);
await new Promise(resolve=>ws.addEventListener('open',resolve,{once:true}));
let serial=0, loaded=null;const pending=new Map(),errors=[];
ws.addEventListener('message',event=>{
  const message=JSON.parse(event.data);
  if(message.id){const request=pending.get(message.id);pending.delete(message.id);clearTimeout(request.timer);message.error?request.reject(message.error):request.resolve(message.result);}
  if(message.method==='Page.loadEventFired'&&loaded){loaded();loaded=null;}
  if(message.method==='Runtime.exceptionThrown')errors.push(message.params.exceptionDetails.text);
});
function cdp(method,params={}){return new Promise((resolve,reject)=>{const id=++serial;const timer=setTimeout(()=>reject(Error(`CDP timeout ${method}`)),30000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});}
async function evaluate(expression){const result=await cdp('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});assert.ok(!result.exceptionDetails,JSON.stringify(result.exceptionDetails));return result.result.value;}
async function navigate(path){const ready=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Page load timeout')),30000);loaded=()=>{clearTimeout(timer);resolve();};});await cdp('Page.navigate',{url:base+path});await ready;}
async function waitFor(expression){return evaluate(`new Promise((resolve,reject)=>{const ready=()=>(${expression});if(ready())return resolve(true);const observer=new MutationObserver(()=>{if(ready()){observer.disconnect();clearTimeout(timer);resolve(true);}});observer.observe(document,{childList:true,subtree:true,attributes:true});const timer=setTimeout(()=>{observer.disconnect();reject(Error('DOM acceptance timeout'));},15000);})`);}
try{
  await cdp('Page.enable');await cdp('Runtime.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1150,deviceScaleFactor:1,mobile:false});
  await navigate('/');
  await waitFor("document.querySelector('#booking-history tr')");
  assert.equal(await evaluate("document.querySelector('#booking-mode').value"),'live');
  assert.equal(await evaluate("document.querySelectorAll('#booking-arm option').length"),5);
  assert.equal(await evaluate("document.querySelectorAll('#booking-policy option').length"),5);
  await evaluate("document.querySelector('#booking-mode').value='replay';document.querySelector('#booking-arm').value='A1';document.querySelector('#booking-policy').value='restricted_release';document.querySelector('#booking-mode').dispatchEvent(new Event('change'));document.querySelector('#booking-policy').dispatchEvent(new Event('change'));document.querySelector('#booking-form').requestSubmit()");
  await waitFor("document.querySelector('#booking-status').textContent==='completed'");
  assert.equal(await evaluate("document.querySelector('#booking-utility').textContent"),'Yes');
  assert.equal(await evaluate("document.querySelector('#booking-recovery').textContent"),'No');
  assert.equal(await evaluate("document.querySelector('#booking-accepted').textContent"),'1');
  assert.equal(await evaluate("document.querySelector('#booking-start').disabled"),false);
  assert.ok(await evaluate("document.querySelector('#booking-model-field').hidden"));
  assert.ok(await evaluate("document.querySelector('#policy-note').textContent.includes('canonical')"));
  assert.ok(await evaluate("document.querySelector('#booking-events').textContent.includes('medical.read')"));
  assert.ok(await evaluate("document.querySelector('#booking-identity').textContent.includes('scripted_replay')"));
  assert.ok(await evaluate("document.querySelector('#booking-events').textContent.includes('booking.evaluated')"));
  const screenshot=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
  await fs.writeFile('.build/core-booking/booking-desktop.png',Buffer.from(screenshot.data,'base64'));
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.ok(await evaluate('document.documentElement.scrollWidth<=window.innerWidth'));
  await navigate('/library');
  assert.ok(await evaluate("Boolean(document.querySelector('#run-form'))"));
  await waitFor("document.querySelectorAll('.scenario-card').length===44 && document.querySelector('.scenario-card.selected')");
  const libraryRows=await evaluate("fetch('/v1/runs?limit=20').then(r=>r.json())");
  assert.ok(libraryRows.length>0 && libraryRows.every(row=>/^C[0-9]{2}$/.test(row.scenario_id)));
  await evaluate("document.querySelector('#mode').value='replay';document.querySelector('#defense').value='content';document.querySelector('#seed').value='31';document.querySelector('#attack').checked=false;document.querySelector('#run-form').requestSubmit()");
  await waitFor("document.querySelector('#run-state')?.textContent==='completed'");
  const libraryRun=await evaluate("new URLSearchParams(location.search).get('run')");
  const libraryReport=await evaluate(`fetch('/v1/runs/${libraryRun}/report').then(r=>r.json())`);
  assert.equal(libraryReport.scenario_id,'C00');assert.equal(libraryReport.benign_task_success,true);
  assert.deepEqual(errors,[]);
  console.log('Booking browser acceptance: honest UI states, actual replay form submission, canonical utility, redacted trace, responsive layout, scoped history and actual C00 library run passed');
}finally{ws.close();}
