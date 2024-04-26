from dataclasses import dataclass
from datetime import datetime

from enumeration import Action
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier
from model.json import JSONPayload


@dataclass
class Payload:
    timestamp: datetime
    node_url: str
    node_id: DeviceIdentifier
    certificate: CustomCertificate
    action: Action

    @staticmethod
    def build(json_data: JSONPayload):
        from certificate.cert_convertor import convert_str_to_cert
        return Payload(
            timestamp=datetime.fromisoformat(json_data.timestamp),
            node_url=json_data.node_url,
            node_id=DeviceIdentifier.from_dict(json_data.node_id),
            certificate=convert_str_to_cert(json_data.cert_string),
            action=getattr(Action, json_data.action_name)
        )
