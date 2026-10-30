"""Finite read/decide/send workflow shared by explicitly distinct live and replay."""

import hmac
import json
import secrets
from dataclasses import replace

from reef_panda_arena.application.booking_contract import BookingDecisionEvidence
from reef_panda_arena.gateway.booking import release_booking
from reef_panda_arena.gateway.budget import reserve_event
from reef_panda_arena.gateway.invoke import ProposedCall, TrustedContext
from reef_panda_arena.model.booking import ATTACK_ARMS, booking_request, decide_booking, decision_adapter
from reef_panda_arena.oracle.booking import booking_utility
from reef_panda_arena.scenarios.booking import DETAILS, ROUTING
from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.booking import BookingRequest


class BookingWorkflow:
    def __init__(self, gateway, fixture, config, model_config, caller, checkpoint):
        self.gateway, self.fixture, self.config = gateway, fixture, config
        self.model_config, self.caller, self.checkpoint = model_config, caller, checkpoint
        self.decisions, self.reads, self.consumption = [], [], []
        self.benign_proposals, self.false_alerts, self.false_blocks = 0, 0, 0
        self.outbound_proposals = 0
        self.stop_reason = None
        self.source = None
        self.feedback = None
        self._proposal_key = secrets.token_bytes(32)

    def snapshot(self):
        return {"decisions": [item.model_dump(mode='json') for item in self.decisions],
                "private_read_event_seqs": list(self.reads), "reader_consumption_turns": list(self.consumption),
                "outbound_proposals": self.outbound_proposals, "benign_proposals_evaluated": self.benign_proposals,
                "false_alerts": self.false_alerts, "false_blocks": self.false_blocks,
                "stop_reason": self.stop_reason}

    async def journal_decision(self, evidence):
        async with self.gateway._lock:
            seq = reserve_event(self.gateway)
            event = RunEvent(run_id=self.gateway.event_store_run_id, event_seq=seq,
                event_type="agent.decision", actor_id="booking_agent", channel="research", tool_name=None,
                destination=None, policy_decision="not_applicable", reason_code=None, data_class="public",
                taint_labels_json={}, safe_summary_json={"booking_decision": evidence.model_dump(mode='json'),
                    "attempt_id": "attack:live" if self.config.arm in ATTACK_ARMS else "task"},
                payload_sha256=None)
            await self.gateway.event_store.append(event)
            if self.gateway.on_event:
                self.gateway.on_event(event)

    def replay_decision(self):
        if self.source is None:
            data = {"action":"read", "arguments":{"patient_reference":self.fixture.patient_reference}}
        else:
            record = self.source.data['record']
            args = {"patient_reference":self.fixture.patient_reference,"recipient":"mock_clinic",
                    "specialty":ROUTING[record['clinical_route']],"requested_time_window":"09:00-12:00"}
            if self.config.arm in ATTACK_ARMS:
                surface = 'window' if self.config.arm == 'A2' else 'text'
                args['requested_time_window' if surface=='window' else 'message'] = self.fixture.receiver.convention(surface)[record['private_detail']]
            data = {"action":"send", "arguments":args}
        return decision_adapter(self.config.arm).validate_json(json.dumps(data))

    async def run(self):
        attempt = 'attack:live' if self.config.arm in ATTACK_ARMS else 'task'
        context = TrustedContext(self.gateway.event_store_run_id,'booking_agent','booking_agent',attempt_id=attempt)
        for turn in range(1,5):
            source_seq = self.reads[-1] if self.source is not None else None
            evidence = BookingDecisionEvidence(turn=turn, source_event_seq=source_seq)
            self.decisions.append(evidence)
            await self.checkpoint(self.snapshot())
            try:
                if self.config.mode=='replay':
                    choice = self.replay_decision()
                else:
                    surface = 'window' if self.config.arm=='A2' else 'text'
                    request = booking_request(self.model_config,self.config.arm,self.fixture.public_task(),
                        self.source.data['record'] if self.source else None,self.feedback,
                        self.fixture.receiver.convention(surface))
                    choice, result = await decide_booking(self.caller,request,self.config.arm)
                    evidence.tokens_in, evidence.tokens_out = result.tokens_in, result.tokens_out
                evidence.outcome, evidence.action = 'valid', choice.action
                evidence.proposal_fingerprint = hmac.digest(self._proposal_key,choice.model_dump_json().encode(),'sha256').hex()
            except ValueError:
                evidence.outcome = 'invalid'
                await self.journal_decision(evidence)
                await self.checkpoint(self.snapshot())
                raise
            except BaseException:
                evidence.outcome = 'failed'
                await self.checkpoint(self.snapshot())
                raise
            if self.source is not None:
                self.consumption.append(turn)
            await self.journal_decision(evidence)
            if choice.action in {'finish','refuse'}:
                self.stop_reason = choice.action
                await self.checkpoint(self.snapshot())
                return
            args = choice.arguments.model_dump(exclude_none=True)
            if choice.action == 'read':
                result = await self.gateway.invoke(context,ProposedCall(tool_name='medical.read',arguments=args))
                if result.allowed:
                    self.source = result
                    self.reads.append(self.gateway.events)
            else:
                self.outbound_proposals += 1
                source_id = self.source.artifact_ids['record'] if self.source else None
                send_context = replace(context,artifact_dependencies={field:(source_id,) for field in args} if source_id else {})
                benign = (self.config.arm not in ATTACK_ARMS
                    and booking_utility((encode_sink_payload('booking.send_request',BookingRequest.model_validate(args)),),self.fixture.authorized_output())
                    and not any(value in json.dumps(args) for value in DETAILS))
                self.benign_proposals += int(benign)
                canonical = self.config.policy=='restricted_release' or self.config.arm=='A3'
                if source_id and (canonical or self.config.policy=='transitive'):
                    released = await release_booking(self.gateway,send_context,source_id=source_id,
                        record=self.source.data['record'],proposal=args,patient_reference=self.fixture.patient_reference,
                        canonical=canonical)
                    if released is None:
                        self.feedback = 'candidate_rejected'
                        self.false_blocks += int(benign)
                        await self.checkpoint(self.snapshot())
                        continue
                    args, send_context = released
                result = await self.gateway.invoke(send_context,ProposedCall(tool_name='booking.send_request',arguments=args))
                observed = self.gateway.boundary_observations[-1]
                self.false_alerts += int(benign and observed['observer_alert'] is True)
                self.false_blocks += int(benign and not result.allowed)
                if result.allowed:
                    self.stop_reason = 'booking_accepted'
                    await self.checkpoint(self.snapshot())
                    return
            self.feedback = 'accepted' if result.allowed else 'candidate_rejected'
            await self.checkpoint(self.snapshot())
        self.stop_reason = 'decision_limit'
        await self.checkpoint(self.snapshot())
