import time
from datetime import datetime
from http import HTTPStatus
from typing import Type

import requests
from flask import flash, current_app, Response
from requests.exceptions import ConnectionError

from certificate.cert_convertor import convert_cert_to_str
from constants import HANDSHAKE_WAITING_TIME, HEARTBEAT_WAITING_TIME
from enumeration import Action, ErrorCategory
from model.db import Transaction
from model.db.auth_transaction import AuthTransaction
from model.json import JSONPayload, JSONConfirmationData, NodeData
from model.json.blockchain_data import BlockchainData
from node.node_base import NodeBase


class NodeSender(NodeBase):

    def send_handshake(self, neighbour_url: str, action: Action) -> bool:

        current_time = datetime.now().isoformat()
        cert_string = convert_cert_to_str(self.my_certificate)
        action_name: str = action.name
        headers = {
            'Content-Type': 'application/json'
        }
        json_data = JSONPayload(timestamp=current_time, node_url=self.url, node_id=self.info.to_dict(),
                                action_name=action_name, cert_string=cert_string)
        json_data.sign_payload(self.my_private_key)
        payload_dict = json_data.to_dict()

        type_desc, type_func, type_url, type_accept_url = action.value
        try:
            response = requests.post(neighbour_url + "/connect", json=payload_dict, headers=headers)
        except ConnectionError:
            flash("Initial connection node not exists.", ErrorCategory.ERROR.value)
            current_app.logger.error(f'Initial connection node with IP {neighbour_url + "/connect"} not exists.')
            return False

        if response.status_code != HTTPStatus.OK:
            flash("Wrong request for handshake.", ErrorCategory.ERROR.value)
            current_app.logger.error(f'Wrong response from handshake response for handshake: {response.content}')

        time.sleep(HANDSHAKE_WAITING_TIME)

        # check confirmation responses
        # at least 1 item is false
        if len(self.confirmations) > 0 and all(item[0] for item in self.confirmations):
            data = JSONConfirmationData(timestamp=current_time, node_url=self.url, node_id=self.info.to_dict(),
                                        cert_string=cert_string, confirmations=list(self.confirmations))
            acceptance_list: list[Response] = []
            for approved, node_url in self.confirmations:
                actual_response = requests.post(node_url + type_accept_url, json=data.to_dict(), headers=headers)
                acceptance_list.append(actual_response)
            if len(list(filter(lambda res: res.status_code != HTTPStatus.OK, acceptance_list))) > 0:
                current_app.logger.error(
                    f'Not passed adding registered node into network. Responses: {acceptance_list}')
                flash("Error with adding new node into network.", ErrorCategory.ERROR.value)
                return False
            self.network_preparation()
            # retrieve data from neighbour node
            response = requests.post(neighbour_url + "/network_data", json=data.to_dict(), headers=headers)

            if response.status_code == HTTPStatus.UNAUTHORIZED:
                current_app.logger.error(f'Authorization error for retrieving data from initial neighbour'
                                         f' {neighbour_url} for connecting node {self.url}')
                flash(response.content.decode('utf-8'), ErrorCategory.ERROR.value)
                self.close_session()
                return False

            elif response.status_code != HTTPStatus.OK:
                current_app.logger.error(f'{response.status_code} {response.content}')
                flash("Error with handling retrieve data request for joining network", ErrorCategory.ERROR.value)
                return False

            try:
                response_json = response.json()
                node_data = BlockchainData.from_dict(response_json)
            except Exception as e:
                current_app.logger.error(
                    f'Error with parsing NodeData for node {self.node_certs} from {neighbour_url}. {e}')
                flash(f"Bad response with nodes data from {neighbour_url}", ErrorCategory.ERROR.value)
                return False
            self.node_certs[self.info.hash_name] = self.my_certificate
            self.init_network_data(node_data)
            return True
        else:
            current_app.logger.info(f"{type_desc} not accepted. {self.confirmations}")
            self.active_nodes.clear()
            self.confirmations = set({})
            flash(f"{type_desc} not accepted.", ErrorCategory.INFO.value)
            return False

    def broadcast_heartbeat(self):
        while True:
            self.__send_heartbeat()
            time.sleep(HEARTBEAT_WAITING_TIME)

    def __send_heartbeat(self):
        # send heartbeat request to remove not active nodes
        # set[tuple[node_url, node_hash]]
        removed_nodes: set[tuple[str, str]] = set({})
        for url, device_hash in self.active_nodes:
            try:
                requests.get(url)
            except (requests.exceptions.RequestException, RecursionError):
                removed_nodes.add((url, device_hash))
        self.active_nodes -= removed_nodes

        # send node data to other nodes to update their active nodes set
        node_certificates = []
        for device_hash, cert in self.node_certs.items():
            node_certificates.append((device_hash, convert_cert_to_str(cert)))
        node_data = NodeData(list(self.active_nodes), list(node_certificates), sender_url=self.url,
                             sender_hash=self.info.hash_name)
        headers = {
            'Content-Type': 'application/json'
        }
        for url in self.get_url_nodes():
            requests.post(url + "/sync", json=node_data.to_dict(), headers=headers)

    def logout_me(self):
        current_time = datetime.now().isoformat()
        if self.my_certificate:
            cert_string = convert_cert_to_str(self.my_certificate)
        else:
            cert_string = ""
        action_name: str = Action.LOGOUT.name
        json_data = JSONPayload(timestamp=current_time, node_url=self.url, node_id=self.info.to_dict(),
                                cert_string=cert_string, action_name=action_name)
        self.generate_trx(AuthTransaction, action_type=Action.LOGOUT.name)
        self.broadcast_request(json_data.to_dict(), "/logout")
        self.pay_transaction_pool = None
        self.pay_blockchain = None
        self.auth_blockchain = None
        self.auth_transaction_pool = None
        self.cert_blockchain = None
        self.cert_transaction_pool = None
        self.node_certs.clear()
        self.active_nodes.clear()
        self.my_certificate = None
        self.my_private_key = None

    def generate_trx(self, trx_class: Type[Transaction], **kwargs):
        transaction = self.create_transaction(trx_class=trx_class, **kwargs)
        payload_dict = {
            "transaction": transaction.to_dict(),
            "type": trx_class.__name__
        }
        self.broadcast_request(payload_dict, '/transaction')
        self.store_transaction(transaction)
