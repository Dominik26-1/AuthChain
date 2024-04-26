from dataclasses import dataclass

from model.common.common import SerializableModel
from model.core.certificate import CustomCertificate


@dataclass
class NodeData(SerializableModel):
    # list[tuple[url, node_hash]]
    active_nodes: list[tuple[str, str]]
    # list[tuple[node_hash, certificate_string_data]]
    node_certs: list[tuple[str, str]]
    sender_url: str
    sender_hash: str

    def get_certs(self) -> dict[str, CustomCertificate]:
        from certificate.cert_convertor import convert_str_to_cert
        certs_map: dict = {}
        for device_hash, cert_data in self.node_certs:
            certs_map[device_hash] = convert_str_to_cert(cert_data)
        return certs_map

    def __eq__(self, other):
        if isinstance(other, NodeData):
            return self.to_dict() == other.to_dict()
        return False
