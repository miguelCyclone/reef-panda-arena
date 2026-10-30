// SVG renderer shared by every scenario. All labels are text nodes.

const ns = 'http://www.w3.org/2000/svg';
function svg(tag, attrs = {}, text = null) {
  const node = document.createElementNS(ns, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text !== null) node.textContent = text;
  return node;
}
const shortRole = (role) => role.replaceAll('_', ' ').replace('worker', '').trim();

export function layoutNodes(scenario, events) {
  const configured = scenario?.visualization?.agents || [];
  const observed = [...new Set(events.map((e) => e.data?.actor_id).filter((id) => id && id !== 'system'))];
  const roster = [...configured, ...observed.filter((id) => !configured.some((a) => a.id === id)).map((id) => ({id, role: id}))];
  const supervisor = roster.find((a) => a.role === 'supervisor');
  const workers = roster.filter((a) => a !== supervisor);
  const columns = workers.length > 4 ? 3 : 2;
  const rows = Math.ceil(workers.length / columns);
  const nodes = workers.map((agent, i) => ({...agent, kind: 'agent',
    x: columns === 3 ? 290 + i % columns * 205 : 350 + i % columns * 285,
    y: 165 + Math.floor(i / columns) * Math.min(118, 245 / Math.max(1, rows - 1)),
  }));
  if (supervisor) nodes.push({...supervisor, kind: 'agent', x: 495, y: 65});
  return [...nodes,
    {id: 'vault', role: 'Private source', kind: 'vault', x: 85, y: 165},
    {id: 'data', role: 'Task data', kind: 'resource', x: 85, y: 365},
    {id: 'memory', role: 'Shared memory', kind: 'resource', x: 495, y: 505},
    {id: 'gateway', role: 'Policy gateway', kind: 'gateway', x: 920, y: 285},
    {id: 'admin', role: 'Admin observer', kind: 'admin', x: 920, y: 85},
    {id: 'sink', role: 'Local sink', kind: 'sink', x: 1100, y: 285},
  ];
}

function curve(from, to) {
  const dx = to.x - from.x, dy = to.y - from.y;
  const edge = (node, direction) => {
    const scale = Math.min(76 / Math.max(1, Math.abs(dx)), 36 / Math.max(1, Math.abs(dy)));
    return {x: node.x + direction * dx * scale, y: node.y + direction * dy * scale};
  };
  const a = edge(from, 1), b = edge(to, -1);
  // Bow past intervening cards so a direct edge never appears to visit them.
  const bowY = Math.abs(dy) < 60 && Math.abs(dx) > 250 ? -82 : 0;
  const bowX = Math.abs(dx) < 60 && Math.abs(dy) > 140 ? 105 : 0;
  return `M ${a.x} ${a.y} C ${a.x + (b.x-a.x)*.4 + bowX} ${a.y + bowY}, ${b.x - (b.x-a.x)*.4 + bowX} ${b.y + bowY}, ${b.x} ${b.y}`;
}

function together(animations) {
  return {
    play() {animations.forEach((a) => a.play());},
    pause() {animations.forEach((a) => a.pause());},
    cancel() {animations.forEach((a) => a.cancel());},
    set currentTime(value) {animations.forEach((a) => {a.currentTime = value;});},
    set playbackRate(value) {animations.forEach((a) => {a.playbackRate = value;});},
    set onfinish(callback) {animations[0].onfinish = callback;},
  };
}

export function drawGraph(root, trace, index, onSelect, reducedMotion) {
  const frame = trace.frames[index];
  const nodes = layoutNodes(trace.scenario, trace.events);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const supervisor = nodes.find((n) => n.role === 'supervisor');
  if (supervisor) byId.set('supervisor', supervisor);
  const attackEnabled = trace.status?.attack_enabled ?? trace.report?.attacker_attempted;
  const compromised = new Set(attackEnabled === false ? []
    : trace.report?.compromised_roles || trace.scenario?.visualization?.compromised_roles || []);
  const diagram = svg('svg', {viewBox: '0 0 1180 560', role: 'group', 'aria-label': 'Agent communication graph'});
  const defs = svg('defs');
  const pattern = svg('pattern', {id: 'flow-dots', width: 22, height: 22, patternUnits: 'userSpaceOnUse'});
  pattern.append(svg('circle', {cx: 1, cy: 1, r: .7, fill: '#35504f'}));
  defs.append(pattern);
  const marker = svg('marker', {id: 'flow-arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: 'auto-start-reverse'});
  marker.append(svg('path', {d: 'M 0 0 L 10 5 L 0 10 z', fill: 'context-stroke'}));
  defs.append(marker); diagram.append(defs, svg('rect', {width: 1180, height: 560, fill: 'url(#flow-dots)'}));
  diagram.append(svg('text', {x: 25, y: 32, class: 'flow-lane-label'}, 'SOURCES'),
    svg('text', {x: 250, y: 32, class: 'flow-lane-label'}, 'AGENT TEAM'),
    svg('text', {x: 865, y: 32, class: 'flow-lane-label'}, 'OUTPUT BOUNDARY'));
  const edges = new Map();
  for (const f of trace.frames.slice(0, index + 1)) {
    if (f.from !== f.to && !f.noPacket && byId.has(f.from) && byId.has(f.to)) edges.set(`${f.from}:${f.to}`, f);
  }
  let activePath = null;
  for (const f of edges.values()) {
    const active = frame && f.from === frame.from && f.to === frame.to && f.stage === frame.stage;
    const path = svg('path', {d: curve(byId.get(f.from), byId.get(f.to)),
      class: `flow-edge${active ? ' active' : ''}${active && (frame.phase === 'attack' || frame.blocked) ? ' hostile' : ''}`,
      'marker-end': 'url(#flow-arrow)', fill: 'none'});
    diagram.append(path);
    if (active) activePath = path;
  }
  const visited = new Set(trace.frames.slice(0, index + 1).flatMap((f) => [f.from, f.to]));
  for (const node of nodes) {
    const active = frame && (node.id === frame.from || node.id === frame.to || frame.stage === 'start' && node === supervisor);
    const rogue = compromised.has(node.id);
    const group = svg('g', {transform: `translate(${node.x},${node.y})`, tabindex: 0, role: 'button',
      'aria-label': `${node.id}: ${node.role}${rogue ? ', compromised actor' : ''}`,
      class: `flow-node ${node.kind}${rogue ? ' rogue' : ''}${active ? ' is-active' : ''}${visited.has(node.id) ? ' visited' : ''}`,
      'data-node': node.id});
    group.append(svg('rect', {x: -70, y: -29, width: 140, height: 62, rx: 13}));
    group.append(svg('text', {x: 0, y: -7, 'text-anchor': 'middle', class: 'flow-node-id'},
      node.kind === 'agent' ? node.id.startsWith('A') && /^A\d+$/.test(node.id) ? node.id : shortRole(node.role).split(' ')[0].toUpperCase() :
      ({vault: 'S  /  PRIVATE', admin: 'OBSERVER', gateway: 'GATEWAY', sink: 'MOCK SINK'}[node.kind] || node.id.toUpperCase())));
    group.append(svg('text', {x: 0, y: 13, 'text-anchor': 'middle', class: 'flow-node-role'}, shortRole(node.role)));
    if (rogue) group.append(svg('text', {x: 0, y: -38, 'text-anchor': 'middle', class: 'flow-rogue-label'}, 'COMPROMISED'));
    if (node.kind === 'agent') group.append(svg('text', {x: 0, y: 47, 'text-anchor': 'middle', class: 'flow-node-status'}, active ? 'ACTIVE' : visited.has(node.id) ? 'EVENT RECORDED' : 'NO BOUNDARY YET'));
    const select = () => onSelect(node);
    group.addEventListener('click', select);
    group.addEventListener('keydown', (event) => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); select();}});
    diagram.append(group);
  }
  root.replaceChildren(diagram);
  let packet = null;
  if (frame && !frame.noPacket && activePath && !frame.blocked) {
    packet = svg('g', {class: `flow-packet ${frame.phase === 'attack' ? 'hostile' : ''}`});
    packet.append(svg('circle', {r: 17}), svg('text', {'text-anchor': 'middle', y: 4}, frame.stage === 'read' && frame.from === 'vault' ? 'S' : frame.phase === 'attack' ? 'f(S)' : frame.secret ? 'S' : '•'));
    diagram.append(packet);
    const length = activePath.getTotalLength();
    const points = Array.from({length: 31}, (_, i) => {
      const p = activePath.getPointAtLength(length * i / 30);
      return {transform: `translate(${p.x}px, ${p.y}px)`};
    });
    if (reducedMotion) {
      const p = activePath.getPointAtLength(length);
      packet.setAttribute('transform', `translate(${p.x},${p.y})`);
    } else return together([packet.animate(points, {duration: 1500, fill: 'forwards', easing: 'ease-in-out'})]);
  }
  const animations = [diagram.animate([{opacity: 1}, {opacity: 1}], {duration: 1500})];
  if (frame?.symbolic) {
    const node = byId.get(frame.from);
    if (node) {
      const chip = svg('g', {transform: `translate(${node.x},${node.y + 73})`, class: 'flow-transform-chip'});
      const output = {decimal_bytes: '[bᵢ]', polynomial_coefficients_v1: '[aᵢ]', base64: 'B64(S)',
        literal: 'S', semantic_summary: 'S[:2]'}[frame.mechanism?.id] || 'f(S)';
      const input = svg('text', {'text-anchor': 'middle', x: -45, y: 4}, 'S');
      const result = svg('text', {'text-anchor': 'middle', x: 28, y: 4}, output);
      chip.append(svg('rect', {x: -72, y: -15, width: 144, height: 28, rx: 14}), input,
        svg('text', {'text-anchor': 'middle', x: -14, y: 4}, '→'), result);
      diagram.append(chip);
      if (!reducedMotion) {
        animations.push(input.animate([{opacity: 1}, {opacity: 1, offset: .3}, {opacity: .35}], {duration: 1500, fill: 'forwards'}),
          result.animate([{opacity: 0}, {opacity: 0, offset: .3}, {opacity: 1}], {duration: 1500, fill: 'forwards'}));
      }
    }
  }
  return together(animations);
}
