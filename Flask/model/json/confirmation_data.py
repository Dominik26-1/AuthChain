from dataclasses import dataclass

from model.json.base import BasePayload


@dataclass
class JSONConfirmationData(BasePayload):
    # tuple[approved, verifier_url]
    confirmations: list[tuple[bool, str]]
