from dataclasses import dataclass

from model.common.common import SerializableModel


@dataclass
class BasePayload(SerializableModel):
    timestamp: str
    node_url: str
    node_id: dict[str, str]
    cert_string: str

