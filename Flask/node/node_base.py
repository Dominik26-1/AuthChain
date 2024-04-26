import uuid
from datetime import datetime
from typing import Type

import requests
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from flask import current_app, session
from sqlalchemy import desc

from certificate.cert_convertor import convert_cert_to_str
from chain import verify_new_block
from constants import TRANSACTION_THRESHOLD
from db import session as db_session
from enumeration import Action
from model.chain import TransactionPool
from model.chain.blockchain import Blockchain
from model.core import ConfirmationData
from model.core.certificate import CustomCertificate
from model.db import Transaction, Block
from model.db.auth_block import AuthBlock, GenesisAuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.cert_block import CertificateBlock, GenesisCertificateBlock
from model.db.cert_transaction import CertificateTransaction
from model.db.pay_block import PaymentBlock, GenesisPaymentBlock
from model.db.pay_transaction import PaymentTransaction
from model.json import NodeData
from model.json.blockchain_data import BlockchainData
from node.node_attributes import NodeAttributes
from utils.string_utils import serialize_transactions


class NodeBase(NodeAttributes):

    def network_preparation(self):
        self.auth_blockchain = Blockchain(GenesisAuthBlock(), AuthBlock)
        self.auth_transaction_pool = TransactionPool([])
        self.pay_blockchain = Blockchain(GenesisPaymentBlock(), PaymentBlock)
        self.pay_transaction_pool = TransactionPool([])
        self.cert_blockchain = Blockchain(GenesisCertificateBlock(), CertificateBlock)
        self.cert_transaction_pool = TransactionPool([])
        self.open_session()

    def get_network_nodes(self):
        active_nodes = self.active_nodes.copy()
        active_nodes.add((self.url, self.info.hash_name))
        return active_nodes

    def init_network_data(self, node_data: BlockchainData):
        self.update_nodes(node_data)

        def db_insert(block_class: Type[Block], trx_class: type, blocks: list[Block], trx: list[Transaction]):
            highest_index_db_block = db_session.query(block_class).order_by(desc(block_class.index)).first()
            if highest_index_db_block is None:
                db_session.add_all(blocks)
            else:
                new_blocks = list(filter(lambda b: b.index > highest_index_db_block.index, blocks))
                db_session.add_all(new_blocks)
            try:
                db_session.commit()
            except Exception as e:
                db_session.rollback()
                current_app.logger.error(f"Error with updating network data - Blocks: {e}")
                return

            latest_db_trx = db_session.query(trx_class).order_by(desc(trx_class.creation_timestamp)).first()
            if latest_db_trx is None:
                db_session.add_all(trx)
            else:
                new_trx = list(filter(lambda t: t.creation_timestamp > latest_db_trx.creation_timestamp, trx))
                db_session.add_all(new_trx)
            try:
                db_session.commit()
            except Exception as e:
                db_session.rollback()
                current_app.logger.error(f"Error with updating network data - Transactions: {e}")
                return

        auth_trx = node_data.get_transactions(AuthTransaction)
        auth_blocks = node_data.get_blocks(AuthBlock)
        pay_trx = node_data.get_transactions(PaymentTransaction)
        pay_blocks = node_data.get_blocks(PaymentBlock)
        cert_trx = node_data.get_transactions(CertificateTransaction)
        cert_blocks = node_data.get_blocks(CertificateBlock)
        db_insert(AuthBlock, AuthTransaction, auth_blocks, auth_trx)
        db_insert(PaymentBlock, PaymentTransaction, pay_blocks, pay_trx)
        db_insert(CertificateBlock, CertificateTransaction, cert_blocks, cert_trx)

        self.auth_transaction_pool = TransactionPool(auth_trx)
        self.pay_transaction_pool = TransactionPool(pay_trx)

        self.auth_blockchain = Blockchain.create(auth_blocks)
        self.pay_blockchain = Blockchain.create(pay_blocks)

    def update_nodes(self, node_data: NodeData):
        sender_url = node_data.sender_url
        sender_hash = node_data.sender_hash
        if sender_url not in self.get_url_nodes() and sender_url != self.url:
            self.active_nodes.add((sender_url, sender_hash))
        other_nodes = set((url, node_hash) for url, node_hash in node_data.active_nodes)
        if (self.url, self.info.hash_name) in other_nodes:
            other_nodes.remove((self.url, self.info.hash_name))
        self.active_nodes.update(other_nodes)
        self.node_certs.update(node_data.get_certs())

    def get_url_nodes(self) -> set[str]:
        return {x[0] for x in self.active_nodes}

    def create_transaction(self, trx_class: Type[Transaction], **kwargs) -> Transaction:
        id = uuid.uuid4().hex
        creation_timestamp = datetime.now()
        node_id = self.info.hash_name
        node_url = self.url
        trx = trx_class(id=id, creation_timestamp=creation_timestamp,
                        node_id=node_id, node_url=node_url, node_name=self.info.common_name, **kwargs)

        trx.sign_transaction(self.my_private_key)
        return trx

    def create_block(self, block_trx: list[Transaction]) -> Block:
        trx_type = block_trx[0]
        trx_data = serialize_transactions(block_trx)
        if isinstance(trx_type, AuthTransaction):
            blockchain: Blockchain = self.auth_blockchain
            block_class = AuthBlock
        elif isinstance(trx_type, PaymentTransaction):
            blockchain: Blockchain = self.pay_blockchain
            block_class = PaymentBlock
        else:
            blockchain: Blockchain = None
            block_class = None

        latest_block = blockchain.get_latest_block()
        all_trx = self.auth_blockchain.get_trx() + self.auth_transaction_pool.transactions
        node_sign_up_trxs: list[AuthTransaction] = list(
            filter(lambda trx: trx.node_id == self.info.hash_name and trx.action_type == Action.SIGNUP.name,
                   all_trx))
        if len(node_sign_up_trxs) > 0:
            sign_up_trx = node_sign_up_trxs[0]
            registration_time = sign_up_trx.creation_timestamp
        else:
            registration_time = datetime.now()
        weight = blockchain.get_blockchain_node_score(block_trx, self.info.hash_name, registration_time)

        return block_class(latest_block.index + 1, datetime.now(), trx_data, latest_block.block_hash, weight,
                           self.info.hash_name)

    def store_transaction(self, transaction: Transaction):
        if isinstance(transaction, AuthTransaction):
            blockchain: Blockchain = self.auth_blockchain
            transaction_pool: TransactionPool = self.auth_transaction_pool
            block_class = AuthBlock
        elif isinstance(transaction, PaymentTransaction):
            blockchain: Blockchain = self.pay_blockchain
            transaction_pool: TransactionPool = self.pay_transaction_pool
            block_class = PaymentBlock
        elif isinstance(transaction, CertificateTransaction):
            blockchain: Blockchain = self.cert_blockchain
            transaction_pool: TransactionPool = self.cert_transaction_pool
            block_class = CertificateBlock
        else:
            return

        transaction_pool.add(transaction)
        db_session.add(transaction)
        try:
            db_session.commit()
        except Exception as e:
            db_session.rollback()
            current_app.logger.error(f"Error with storing transaction {transaction}: {e}")

        if len(transaction_pool.transactions) >= TRANSACTION_THRESHOLD:
            if transaction_pool.get_block_creator_id() == self.info.hash_name:
                block_transactions = transaction_pool.get_block_trx()

                block = self.create_block(block_transactions)
                if not verify_new_block(blockchain, block, transaction_pool):
                    current_app.logger.error(f"Verification of newly created block not passed on block creator node: {block.to_dict()}")
                    return
                blockchain.add(block)
                transaction_pool.clear_block_trx()
                db_session.add(block)
                try:
                    db_session.commit()
                except Exception as e:
                    db_session.rollback()
                    current_app.logger.error(f"Error with creating block {block}: {e}")
                payload_data = {
                    "type": block_class.__name__,
                    "block": block.to_dict()
                }
                self.broadcast_request(payload_data, '/block')

    def verify_approval(self, confirmations: set[tuple[bool, str]]) -> bool:
        return len(confirmations) > 0 and all(item[0] for item in confirmations)

    def broadcast_request(self, json_data, target_url_suffix: str):
        headers = {
            'Content-Type': 'application/json'
        }
        if target_url_suffix == '/logout':
            current_app.logger.info(f'broadcasting logout for {self.get_url_nodes()}')
        for url in self.get_url_nodes():
            response = requests.post(url + target_url_suffix, json=json_data, headers=headers)

    def get_network_data(self, confirmation_data: ConfirmationData) -> BlockchainData | None:
        confirmations = confirmation_data.confirmations
        current_app.logger.debug(f"verification: {confirmations}")
        if self.verify_approval(confirmations):
            return self.get_blockchain_data()

    def get_blockchain_data(self) -> BlockchainData:
        node_certificates = []
        for device_hash, cert in self.node_certs.items():
            node_certificates.append((device_hash, convert_cert_to_str(cert)))
        return BlockchainData(active_nodes=list(self.active_nodes), node_certs=list(node_certificates),
                              sender_url=self.url,
                              sender_hash=self.info.hash_name, pay_blocks=self.pay_blockchain.get_block_dict(),
                              pay_transactions=self.pay_transaction_pool.get_trx_dict(),
                              auth_blocks=self.auth_blockchain.get_block_dict(),
                              auth_transactions=self.auth_transaction_pool.get_trx_dict(),
                              cert_blocks=self.cert_blockchain.get_block_dict(),
                              cert_transactions=self.cert_transaction_pool.get_trx_dict(),
                              )

    def set_credentials(self, cert: CustomCertificate, private_key: PrivateKeyTypes):
        self.my_certificate = cert
        self.my_private_key = private_key

    def open_session(self):
        session['pc_id'] = self.info.hash_name

    def close_session(self):
        session.pop('pc_id', None)

    def is_logged(self) -> bool:
        return session.get('pc_id') == self.info.hash_name
