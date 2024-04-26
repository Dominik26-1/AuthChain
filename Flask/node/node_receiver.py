from http import HTTPStatus
from typing import Type

import requests
from flask import flash, current_app

from certificate.cert_verifier import verify_cert, verify_text
from chain import verify_new_block
from db import session as db_session
from enumeration import Action, ErrorCategory
from model.chain.blockchain import Blockchain
from model.core import ConfirmationData, Payload
from model.core.certificate import CustomCertificate
from model.db import Block, Transaction
from model.db.auth_block import AuthBlock
from model.db.pay_block import PaymentBlock
from model.device import DeviceIdentifier
from model.json import JSONPayload
from model.json.blockchain_data import BlockchainData
from node.node_base import NodeBase


class NodeReceiver(NodeBase):

    def receive_handshake(self, json_payload: JSONPayload):

        payload_data = Payload.build(json_payload)
        sender_certificate: CustomCertificate = payload_data.certificate
        device = payload_data.node_id
        action: Action = payload_data.action
        sender_url = payload_data.node_url

        first_approval = verify_cert(sender_certificate, self.ca_cert, device)
        sender_device_hash = device.hash_name
        exiting_cert = self.node_certs.get(sender_device_hash)

        action_value, verify_function, url, accept_url = action.value
        second_approval = verify_function(actual_cert=sender_certificate, existing_cert=exiting_cert,
                                          device_id=device)
        third_approval = verify_text(sender_certificate, json_payload.signature, json_payload.get_fingerprint())
        current_app.logger.info(f"approvals: {first_approval} {second_approval} {third_approval}")
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.post(sender_url + "/confirmation",
                                 json={"approved": all([first_approval, second_approval, third_approval]),
                                       "node_url": self.url},
                                 headers=headers)
        if response.status_code != HTTPStatus.OK:
            flash(f"Error with confirmation of handshake for {self.url}", ErrorCategory.ERROR.value)
            current_app.logger.error(
                f"Error with confirmation of handshake for {self.url}. {response.status_code} {response.content}")

    def register_another_node(self, confirmation_data: ConfirmationData) -> bool:
        confirmations = confirmation_data.confirmations
        joining_node_url = confirmation_data.node_url
        device = confirmation_data.node_id
        if not self.verify_approval(confirmations):
            flash(f"Register verification with confirmation data failed for {joining_node_url}",
                  ErrorCategory.WARNING.value)
            current_app.logger.warning(
                f"Register verification with confirmation data failed for {joining_node_url} with hash {device.hash_name}")
            return False

        if self.node_certs.get(device.hash_name):
            flash(f"Already registered node {joining_node_url}", ErrorCategory.WARNING.value)
            current_app.logger.warning(
                f"Already registered node {joining_node_url} with hash_name {device.hash_name}")
            return False

        applier_cert = confirmation_data.certificate
        if self.info.hash_name != device.hash_name:
            self.node_certs[device.hash_name] = applier_cert
            self.active_nodes.add((joining_node_url, device.hash_name))
        return True

    def login_another_node(self, confirmation_data: ConfirmationData) -> bool:
        confirmations = confirmation_data.confirmations
        device = confirmation_data.node_id
        joining_node_url = confirmation_data.node_url
        if not self.verify_approval(confirmations):
            flash(f"Login verification with confirmation data failed for {joining_node_url}",
                  ErrorCategory.WARNING.value)
            current_app.logger.warning(
                f"Login verification with confirmation data failed for {joining_node_url} with hash {device.hash_name}")
            return False

        if not self.node_certs.get(device.hash_name):
            flash(f"Not registered node {joining_node_url}", ErrorCategory.WARNING.value)
            current_app.logger.warning(
                f"Not registered node {joining_node_url} with hash_name {device.hash_name}")
            return False
        if self.info.hash_name != device.hash_name:
            self.active_nodes.add((joining_node_url, device.hash_name))
        return True

    def logout_another_node(self, node_url: str, device_id: DeviceIdentifier) -> bool:
        if (node_url, device_id.hash_name) in self.active_nodes:
            # self.active_nodes.remove((node_url, device_id.hash_name))
            return True
        current_app.logger.warning(f"Not successfull logout for {node_url} and {device_id.hash_name}")
        return False

    def update_another_node(self, confirmation_data: ConfirmationData) -> bool:
        confirmations = confirmation_data.confirmations
        applier_cert = confirmation_data.certificate
        device = confirmation_data.node_id
        joining_node_url = confirmation_data.node_url
        if not self.node_certs.get(device.hash_name):
            flash(f"Not registered node {joining_node_url}", ErrorCategory.ERROR.value)
            current_app.logger.error(
                f"Not registered node {joining_node_url} with hash_name {device.hash_name}")
            return False

        if not self.verify_approval(confirmations):
            flash(f"Update verification with confirmation data failed for {joining_node_url}",
                  ErrorCategory.WARNING.value)
            current_app.logger.warning(
                f"Update verification with confirmation data failed for {joining_node_url} with hash {device.hash_name}")
            return False

        self.node_certs[device.hash_name] = applier_cert
        return True

    def handle_confirmation(self, approved: bool, verifier_url):
        self.confirmations.add((approved, verifier_url))

    def receive_block(self, block: Block):
        if isinstance(block, AuthBlock):
            blockchain = self.auth_blockchain
            transaction_pool = self.auth_transaction_pool
        else:
            blockchain = self.pay_blockchain
            transaction_pool = self.pay_transaction_pool
        longest_chain = self.sync_blockchain(block.__class__)
        if blockchain.get_latest_block().index + 1 != block.index:
            blockchain = longest_chain
            db_session.query(block.__class__).delete()
            try:
                db_session.commit()
            except Exception as e:
                db_session.rollback()
                current_app.logger.error(f"Error with replacing blockchain in database: {e}")

        if verify_new_block(blockchain, block, transaction_pool):
            blockchain.add(block)
            db_session.add(block)
            db_session.commit()
            transaction_pool.clear_block_trx()

    def handle_transaction(self, trx: Transaction):
        device_hash = trx.node_id
        sender_cert = self.node_certs.get(device_hash)
        verified = verify_text(sender_cert, trx.signature, trx.serialize())
        if verified:
            self.store_transaction(trx)
        else:
            current_app.logger.warning(f"Wrong signature. Rejected transaction : {trx}")

    def sync_blockchain(self, block_type: Type[Block]) -> Blockchain:
        blockchain_data: list[BlockchainData] = []
        for url, node_hash in self.active_nodes:
            response = requests.get(url + "/blockchain_data")
            try:
                response_json = response.json()
                blockchain_data.append(BlockchainData.from_dict(response_json))
            except Exception as e:
                current_app.logger.error(
                    f'Error with parsing Blockchain data for node {self.info.hash_name} from {url}. {e}')
                return False
        if block_type is AuthBlock:
            blockchains: list[Blockchain] = list(
                map(lambda blk: Blockchain.create(blk.get_blocks(AuthBlock)), blockchain_data))
        else:
            blockchains: list[Blockchain] = list(
                map(lambda blk: Blockchain.create(blk.get_blocks(PaymentBlock)), blockchain_data))
        blockchains.sort(key=lambda chain: chain.get_blockchain_length(), reverse=True)
        return blockchains[0]
