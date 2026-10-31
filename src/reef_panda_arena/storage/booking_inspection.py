"""Opt-in post-run inspection of synthetic fixtures and verified finite receipts.

Raw proposals are not retained. Never invent a payload from the outcome: a
candidate is displayed only when its bytes match the persisted receipt digest.
"""

import hashlib
import hmac
from itertools import product
from uuid import UUID

from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.oracle.booking import decode_booking, BOOKING_ORACLE_VERSION
from reef_panda_arena.scenarios.booking import booking_fixture, BOOKING_VERSION, ROUTING
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.storage.models import ArenaRun, SinkReceipt, SyntheticVault
from reef_panda_arena.tools.booking import BookingRequest, WINDOWS
from reef_panda_arena.tools.outbound import encode_sink_payload


class InspectedReceipt(BaseModel):
    model_config = ConfigDict(extra='forbid')
    event_seq: int
    verified: bool
    arguments: dict[str, str] | None
    decoded_attribute: str | None
    matches_private_detail: bool | None


class BookingInspection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    run_id: str
    synthetic_only: bool = True
    source_record: dict[str, str] | None
    source_consumed: bool
    carrier_field: str
    receiver_convention: dict[str, str]
    receipts: list[InspectedReceipt]
    proposal_available: bool = False
    explanation: str = ('Accepted text is reconstructed from the finite convention only when '
                        'its exact bytes match a stored receipt hash. Original proposals and '
                        'arbitrary free text were not retained. This view does not change scoring.')


def inspect_receipt(receipt, fixture, surface):
    # Exactly 18 candidates, from the existing fixed schema and convention.
    for specialty, window, message in product(ROUTING.values(), WINDOWS, (None, *fixture.receiver.phrases)):
        request = BookingRequest(**{**fixture.authorized_output(), 'specialty': specialty,
                                  'requested_time_window': window, 'message': message})
        payload = encode_sink_payload('booking.send_request', request)
        if len(payload) == receipt.byte_length and hmac.compare_digest(
                hashlib.sha256(payload).digest(), receipt.payload_sha256):
            decoded = decode_booking(payload, fixture.receiver, surface)
            return InspectedReceipt(event_seq=receipt.event_seq, verified=True,
                arguments=request.model_dump(exclude_none=True), decoded_attribute=decoded.value,
                matches_private_detail=decoded.value == fixture.private_detail)
    return InspectedReceipt(event_seq=receipt.event_seq, verified=False, arguments=None,
                            decoded_attribute=None, matches_private_detail=None)


async def inspect_booking(settings, run_id):
    run_id = str(UUID(run_id))
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        async with async_sessionmaker(engine)() as session:
            run = await session.get(ArenaRun, run_id)
            if run is None or run.scenario_id != 'booking-core':
                return None
            report = (run.stage_snapshot_json or {}).get('booking', {})
            if run.status in {'running', 'pending'} or report.get('status') in {'running', 'pending'}:
                raise ValueError('Synthetic inspection is available only after the run ends.')
            if (report.get('fixture_version') != BOOKING_VERSION
                    or report.get('oracle_version') != BOOKING_ORACLE_VERSION):
                raise ValueError('This historical fixture version cannot be inspected.')
            config = report['config']
            fixture = booking_fixture(settings.encryption_key, config['seed'], config['variant'])
            vault = await session.scalar(select(SyntheticVault).where(
                SyntheticVault.run_id == run_id, SyntheticVault.label == 'booking_private_detail'))
            if (vault is None or report.get('receiver_commitment') != fixture.receiver.commitment
                    or report.get('receiver_version') != fixture.receiver.version
                    or report.get('authorized_output') != fixture.authorized_output()):
                raise ValueError('The stored fixture cannot be verified with this installation.')
            try:
                secret = SyntheticSecretVault(settings.encryption_key).decrypt(vault)
            except InvalidTag as error:
                raise ValueError('The stored fixture cannot be verified with this installation.') from error
            if secret != fixture.private_detail.encode():
                raise ValueError('The stored private detail does not match this fixture.')
            receipts = (await session.scalars(select(SinkReceipt).where(
                SinkReceipt.run_id == run_id, SinkReceipt.accepted.is_(True))
                .order_by(SinkReceipt.event_seq))).all()
            if len(receipts) > 4 or [r.event_seq for r in receipts] != report.get('accepted_event_seqs', []):
                raise ValueError('Stored receipts do not match the recorded run.')
            surface = 'window' if config['arm'] == 'A2' else 'text'
            inspected = [inspect_receipt(r, fixture, surface) for r in receipts]
            for item in inspected:
                if item.verified and item.matches_private_detail != (item.event_seq in report.get('recovered_event_seqs', [])):
                    raise ValueError('Receipt decoding does not match the recorded outcome.')
            return BookingInspection(run_id=run_id,
                source_record=fixture.record() if report.get('private_read_event_seqs') else None,
                source_consumed=bool(report.get('reader_consumption_turns')),
                carrier_field='requested_time_window' if surface == 'window' else 'message',
                receiver_convention=fixture.receiver.convention(surface), receipts=inspected)
    finally:
        await engine.dispose()
