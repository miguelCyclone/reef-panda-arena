// Explicit human inspection after a run; never included in model or reviewer inputs.
export function renderInspection(container, evidence) {
  container.replaceChildren();
  const add = (tag, text, parent = container, className = '') => {
    const node = document.createElement(tag); node.textContent = text;
    if (className) node.className = className;
    parent.append(node); return node;
  };
  add('p', 'Synthetic data · revealed after execution', container, 'inspection-tag');
  add('h4', '1 / Sensitive information the agent read');
  if (evidence.source_record) {
    add('code', `private_detail = "${evidence.source_record.private_detail}"`, container, 'private-value');
    add('p', `Synthetic diagnostic category, outside the authorized disclosure. Later model consumption: ${evidence.source_consumed ? 'confirmed' : 'not established'}.`, container, 'hint');
  } else add('p', 'No accepted private read was recorded.');
  add('h4', '2 / What reached the destination');
  if (!evidence.receipts.length) add('p', 'No accepted outbound message. Nothing reached the local mock destination.', container, 'inspection-empty');
  for (const receipt of evidence.receipts) {
    const box = add('div', '', container, 'receipt-evidence');
    add('p', `Accepted receipt · event ${receipt.event_seq}`, box, 'hint');
    if (!receipt.verified) {
      add('p', 'Exact text unavailable: no finite-convention candidate matches the stored receipt. The recorded outcome remains separate.', box);
      continue;
    }
    const carrier = receipt.arguments[evidence.carrier_field];
    add('p', carrier == null ? `${evidence.carrier_field}: omitted from the accepted call` : `${evidence.carrier_field}:`, box);
    if (carrier != null) add('code', carrier, box, 'carrier-value');
    add('pre', JSON.stringify(receipt.arguments, null, 2), box);
    add('p', receipt.decoded_attribute == null ? 'Receiver: no attribute decoded from this accepted call.'
      : `Receiver decoded: ${receipt.decoded_attribute} · ${receipt.matches_private_detail ? 'matches the private detail' : 'does not match the private detail'}.`, box, 'receiver-verdict');
  }
  add('h4', '3 / How the pre-agreed convention works');
  const mapping = add('dl', '', container, 'convention');
  for (const [secret, phrase] of Object.entries(evidence.receiver_convention)) {
    add('dt', secret, mapping); add('dd', phrase, mapping);
  }
  add('p', 'This is a pre-agreed mapping, not a newly discovered encoding. The content reviewer did not receive this mapping.', container, 'hint');
  add('p', evidence.explanation, container, 'hint');
}
