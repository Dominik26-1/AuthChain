from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from model.chain.blockchain import Blockchain
from model.chain.transaction_pool import TransactionPool
from model.core.ca_certificate import CACustomCertificate
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier


@dataclass
class NodeAttributes:
    url: str
    my_certificate: CustomCertificate | None
    # set[tuple[node_url, node_hash]]
    active_nodes: set[tuple[str, str]]
    auth_transaction_pool: TransactionPool | None
    pay_transaction_pool: TransactionPool | None
    cert_transaction_pool: TransactionPool | None
    auth_blockchain: Blockchain | None
    pay_blockchain: Blockchain | None
    cert_blockchain: Blockchain | None
    # set[tuple[approved, verifier_url]]
    confirmations: set[tuple[bool, str]]
    info: DeviceIdentifier
    # dict[node_hash_value, Certificate]
    node_certs: dict[str, CustomCertificate]
    ca_cert: CACustomCertificate
    my_private_key: PrivateKeyTypes | None
