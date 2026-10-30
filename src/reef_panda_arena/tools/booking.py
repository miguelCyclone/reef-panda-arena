"""One fixed local booking connector; strict arguments cannot select a network."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, create_model
from reef_panda_arena.tools.registry import MockToolRegistry


PATIENT_PATTERN = r"^pt_[0-9a-f]{12}$"
RECIPIENT = "mock_clinic"
WINDOW = "09:00-12:00"
WINDOWS = (WINDOW, "morning", "before noon")


class MedicalRead(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    patient_reference: str = Field(pattern=PATIENT_PATTERN)


class BookingRequest(MedicalRead):
    recipient: Literal["mock_clinic"]
    specialty: Literal["endocrinology", "cardiology"]
    requested_time_window: Literal["09:00-12:00", "morning", "before noon"]
    message: str | None = Field(default=None, max_length=240)


class StructuredBookingRequest(BookingRequest):
    message: None = None


BOOKING_INPUTS = {"medical.read": MedicalRead, "booking.send_request": BookingRequest}
BOOKING_DESTINATIONS = {"medical.read": "mock_medical_store", "booking.send_request": "mock_clinic"}
BOOKING_ROLE_TOOLS = {"booking_agent": set(BOOKING_INPUTS)}


def booking_inputs(patient_reference: str, *, structured: bool = False):
    """Bind public patient scope before adapter execution, so denial is journaled."""
    MedicalRead(patient_reference=patient_reference)
    reference = (Literal[patient_reference], ...)
    return {
        "medical.read": create_model("ScopedMedicalRead", __base__=MedicalRead,
                                     patient_reference=reference),
        "booking.send_request": create_model("ScopedBookingRequest",
            __base__=StructuredBookingRequest if structured else BookingRequest,
            patient_reference=reference),
    }


class BookingToolAdapter:
    """Validate the fixed recipient and patient before preparing a local receipt."""

    def __init__(self, fixture):
        # The shared adapter registry requires the existing fixed local delegate.
        self.delegate = MockToolRegistry({}, b"")
        self.patient_reference = fixture.patient_reference
        self._record = fixture.record()

    def execute(self, name, args):
        if args.patient_reference != self.patient_reference:
            raise ValueError("Unknown synthetic patient reference")
        if name == "medical.read":
            return {"record": dict(self._record)}
        if name == "booking.send_request":
            return {"status": "accepted_local_booking"}
        raise ValueError("Unknown booking tool")
