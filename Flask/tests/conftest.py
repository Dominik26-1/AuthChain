import os
import threading
from unittest.mock import MagicMock

import pytest

import config
from certificate.cert_generator import generate_certificate
from certificate.cert_loader import load_certificate
from certificate.cert_saver import save_certificate, save_private_key
from config import Config
from enumeration import Action
from model.chain import TransactionPool
from model.chain.blockchain import Blockchain
from model.db.auth_block import GenesisAuthBlock, AuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.cert_block import GenesisCertificateBlock, CertificateBlock
from model.db.pay_block import GenesisPaymentBlock, PaymentBlock
from model.db.pay_transaction import PaymentTransaction
from node import Node


# Backup the original CERT_FOLDER_PATH
ORIGINAL_CERT_FOLDER_PATH = config.Config.CERT_FOLDER_PATH

@pytest.fixture(scope='session', autouse=True)
def set_cert_folder_path():
    # Set the CERT_FOLDER_PATH to the test certs directory
    config.Config.CERT_FOLDER_PATH = os.path.join(config.Config.BASE_DIR, 'tests', 'certs', '')
    yield
    # Restore the original CERT_FOLDER_PATH after tests
    config.Config.CERT_FOLDER_PATH = ORIGINAL_CERT_FOLDER_PATH

@pytest.fixture(autouse=True)
def main_node(folder_test, monkeypatch):
    thread_mock = MagicMock()
    #monkeypatch.setattr(config.Config, 'CERT_FOLDER_PATH', os.path.join(config.Config.BASE_DIR, *['tests', 'certs', '']))
    monkeypatch.setattr(threading, 'Thread', thread_mock)
    example_node = Node("PCtest", "10.126.147.15", 8443, "80:c2:15:f4:14", "model", "SN123456")
    example_node.auth_transaction_pool = TransactionPool([])
    example_node.auth_blockchain = Blockchain(GenesisAuthBlock(), AuthBlock)
    example_node.cert_transaction_pool = TransactionPool([])
    example_node.cert_blockchain = Blockchain(GenesisCertificateBlock(), CertificateBlock)
    example_node.pay_transaction_pool = TransactionPool([])
    example_node.pay_blockchain = Blockchain(GenesisPaymentBlock(), PaymentBlock)
    thread_mock.assert_called_once()
    cert, key = generate_certificate(example_node.info)
    save_certificate(cert, folder_test, 'my_cert.pem')
    save_private_key(key, folder_test, 'private_key.key')
    example_node.set_credentials(cert, key)
    example_node.active_nodes.add(("https://10.126.147.18:8443/api", "asdfqwe55"))
    example_node.active_nodes.add(("https://10.126.147.16:8443/api", "asdfqwe55feljn"))
    example_node.active_nodes.add(("http://10.126.147.17:8443/api", "efoneafn4geg4b"))
    example_node.node_certs.update({
        "asdfqwe55": load_certificate('ca_cert.pem', folder_test),
        "asdfqwe55feljn": load_certificate('ca_cert.pem', folder_test),
        "efoneafn4geg4b": load_certificate('ca_cert.pem', folder_test)
    })
    example_node.auth_transaction_pool.add(
        example_node.create_transaction(AuthTransaction, action_type=Action.SIGNUP.name))
    example_node.auth_transaction_pool.add(
        example_node.create_transaction(AuthTransaction, action_type=Action.LOGIN.name))
    example_node.auth_transaction_pool.add(
        example_node.create_transaction(AuthTransaction, action_type=Action.LOGOUT.name))
    example_node.auth_transaction_pool.add(
        example_node.create_transaction(AuthTransaction, action_type=Action.LOGIN.name))

    example_node.pay_transaction_pool.add(
        example_node.create_transaction(PaymentTransaction, price=70.4))
    example_node.pay_transaction_pool.add(
        example_node.create_transaction(PaymentTransaction, price=740.4))
    example_node.pay_transaction_pool.add(
        example_node.create_transaction(PaymentTransaction, price=707.4))
    example_node.pay_transaction_pool.add(
        example_node.create_transaction(PaymentTransaction, price=65445))
    example_node.node_certs[example_node.info.hash_name] = example_node.my_certificate

    return example_node


@pytest.fixture(autouse=True)
def app(monkeypatch, main_node):
    def create_node_instance_mock(name, ip_address, port, mac_address, model, serial_number):
        # Tu môžete definovať vlastnú mock funkciu, ktorá simuluje správanie create_node_instance
        return main_node

    monkeypatch.setattr('node.node_instance.create_node_instance', create_node_instance_mock)
    monkeypatch.setattr(config.Config, 'SQLALCHEMY_DATABASE_URI', 'sqlite:///:memory:')
    monkeypatch.setattr(config.Config, 'CERT_FOLDER_PATH', os.path.join(config.Config.BASE_DIR, *['tests', 'certs', '']))
    # monkeypatch.setattr('app.create_node_instance', create_node_instance_mock)
    thread_mock = MagicMock()
    monkeypatch.setattr(threading, 'Thread', thread_mock)
    from app import app as flask_app
    flask_app.config.update({
        "TESTING": True,
        'PUBLIC_IP': 'test_ip',
        'DEVICE_NAME': 'PC1',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'PORT': '5000',
        'MAC_ADDRESS': 'dummy',
        'MODEL': 'model',
        'SERIAL_NUMBER': 'SN1',
        'CERT_FOLDER_PATH': os.path.join(os.path.dirname(os.path.abspath(__file__)), *['static', 'test', '']),
        'CA_FOLDER_PATH': os.path.join(os.path.dirname(os.path.abspath(__file__)), *['static', 'test', ''])
        # Ďalšie konfigurácie špecifické pre testovanie
    })

    # Iné nastavenia ak sú potrebné (napr. databáza)
    flask_app.logger.disabled = True
    yield flask_app


@pytest.fixture(autouse=True)
def client(app, monkeypatch):
    return app.test_client()


@pytest.fixture(autouse=True)
def folder_test():
    return os.path.join(Config.BASE_DIR, *['static', 'test', ''])


@pytest.fixture(autouse=True)
def sender_node(folder_test, monkeypatch):
    thread_mock = MagicMock()
    monkeypatch.setattr(threading, 'Thread', thread_mock)
    example_node = Node("PCtest2", "10.126.147.99", 8443, "80:c2:15:f4:18", "model2", "SN12354456")
    cert, key = generate_certificate(example_node.info)
    save_certificate(cert, folder_test, 'my_cert2.pem')
    save_private_key(key, folder_test, 'private_key2.key')
    example_node.set_credentials(cert, key)

    return example_node
