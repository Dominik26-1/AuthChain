import threading

from certificate.cert_loader import load_certificate
from config import Config
from constants import CA_CERT_NAME
from model.chain import TransactionPool
from model.chain.blockchain import Blockchain
from model.core.ca_certificate import CACustomCertificate
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier
from node.node_receiver import NodeReceiver
from node.node_sender import NodeSender


class Node(NodeReceiver, NodeSender):
    def __init__(self, name, ip_address, port: int, mac_address: str, model: str, serial_number):
        self.url = f"https://{ip_address}:{port}/api"
        # set[tuple[node_url, node_hash]]
        self.active_nodes: set[tuple[str, str]] = set({})
        self.auth_transaction_pool: TransactionPool | None = None
        self.pay_transaction_pool: TransactionPool | None = None
        self.pay_transaction_pool: TransactionPool | None = None
        self.cert_transaction_pool: TransactionPool | None = None
        self.auth_blockchain: Blockchain | None = None
        self.pay_blockchain: Blockchain | None = None
        self.cert_blockchain: Blockchain | None = None
        # set[tuple[approved, verifier_url]]
        self.confirmations: set[tuple[bool, str]] = set({})
        self.info: DeviceIdentifier = DeviceIdentifier(name, serial_number, mac_address, model)
        # dict[node_hash_value, CustomCertificate]
        self.node_certs: dict[str, CustomCertificate] = {}
        self.ca_cert: CACustomCertificate = load_certificate(CA_CERT_NAME, Config.CERT_FOLDER_PATH, True)
        self.my_private_key = None
        self.my_certificate = None
        threading.Thread(target=lambda: self.broadcast_heartbeat()).start()
