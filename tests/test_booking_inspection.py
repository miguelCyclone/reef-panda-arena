"""Inspect only verified accepted bytes; never infer a message from a score."""
import hashlib
from types import SimpleNamespace
from reef_panda_arena.scenarios.booking import booking_fixture
from reef_panda_arena.storage.booking_inspection import inspect_receipt
from reef_panda_arena.tools.booking import BookingRequest
from reef_panda_arena.tools.outbound import encode_sink_payload


def test_receipt_inspection_requires_exact_bytes_and_decodes_independently():
    fixture = booking_fixture(b'x' * 32, 31, 0)
    for message in (fixture.receiver.convention('text')[fixture.private_detail], None, 'Unretained free text'):
        request = BookingRequest(**fixture.authorized_output(), message=message)
        payload = encode_sink_payload('booking.send_request', request)
        receipt = SimpleNamespace(event_seq=4, byte_length=len(payload), payload_sha256=hashlib.sha256(payload).digest())
        result = inspect_receipt(receipt, fixture, 'text')
        if message == 'Unretained free text':
            assert not result.verified and result.arguments is None and result.matches_private_detail is None
        else:
            assert result.verified and result.arguments == request.model_dump(exclude_none=True)
            assert result.matches_private_detail is (message is not None)
        receipt.byte_length += 1
        assert not inspect_receipt(receipt, fixture, 'text').verified
