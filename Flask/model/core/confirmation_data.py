from dataclasses import dataclass
from datetime import datetime

from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier
from model.json import JSONConfirmationData


@dataclass
class ConfirmationData:
    timestamp: datetime
    node_url: str
    node_id: DeviceIdentifier
    certificate: CustomCertificate
    confirmations: set[tuple[bool, str]]

    @staticmethod
    def build(json_data: JSONConfirmationData):
        from certificate.cert_convertor import convert_str_to_cert
        return ConfirmationData(
            timestamp=datetime.fromisoformat(json_data.timestamp),
            node_url=json_data.node_url,
            node_id=DeviceIdentifier.from_dict(json_data.node_id),
            certificate=convert_str_to_cert(json_data.cert_string),
            confirmations={tuple(inner_list) for inner_list in json_data.confirmations}
        )
