import threading
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Query

from certificate.cert_convertor import convert_cert_to_str
from certificate.cert_loader import load_certificate
from db import session
from model.core import ConfirmationData
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier
from model.json import NodeData
from node import Node


def test_logout_yourselves(main_node, monkeypatch, app):
    monkeypatch.setattr(main_node, "broadcast_request", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    main_node.logout_me()

    assert main_node.is_logged() is False
    assert main_node.auth_transaction_pool is None
    assert main_node.auth_blockchain is None
    assert len(main_node.active_nodes) == 0
    assert len(main_node.node_certs) == 0
    assert main_node.my_certificate is None


def test_node_creation(monkeypatch):
    thread_mock = MagicMock()
    monkeypatch.setattr(threading, 'Thread', thread_mock)
    test_node = Node("PCtest", "10.126.147.15", 8443, "80:c2:15:f4:14", "model", "SN123456")
    assert test_node.url == "https://10.126.147.15:8443/api"
    assert test_node.is_logged() is False
    assert test_node.auth_blockchain is None
    assert test_node.pay_blockchain is None
    assert test_node.auth_transaction_pool is None
    assert test_node.pay_transaction_pool is None
    assert test_node.my_certificate is None
    assert test_node.my_private_key is None
    assert len(test_node.node_certs) == 0
    assert len(test_node.active_nodes) == 0


def test_add_node_data(main_node, folder_test):
    cert = convert_cert_to_str(load_certificate('ca_cert.pem', folder_test))
    node_data = NodeData(active_nodes=[
        ("https://10.126.147.15:8443/api", "73e3e53d80c8ff5a6e213a126f9bc50ce8f895cadf8ea96ad0cffc453c21511d"),
        ("https://10.126.147.16:8443/api", "asdfqwe55feljn"),
        ("https://10.126.147.20:8443/api", "fdnvPFNVjn5fvfdb")],
        node_certs=[
            ("73e3e53d80c8ff5a6e213a126f9bc50ce8f895cadf8ea96ad0cffc453c21511d", cert),
            ("asdfqwe55feljn", cert),
            ("fdnvPFNVjn5fvfdb", cert)],
        sender_url="https://10.126.147.23:8443/api",
        sender_hash="skuskaHash1"
    )
    main_node.update_nodes(node_data)

    assert len(main_node.active_nodes) == 5
    assert "https://10.126.147.20:8443/api" in main_node.get_url_nodes()
    assert "https://10.126.147.23:8443/api" in main_node.get_url_nodes()
    assert main_node.url == "https://10.126.147.15:8443/api"
    assert "https://10.126.147.15:8443/api" not in main_node.get_url_nodes()

    assert len(main_node.node_certs) == 5
    assert main_node.node_certs.get("73e3e53d80c8ff5a6e213a126f9bc50ce8f895cadf8ea96ad0cffc453c21511d") is not None


@pytest.mark.parametrize(
    "confirmations, result",
    [({(True, ''), (True, ''), (True, '')}, True),
     ({(True, ''), (False, ''), (True, '')}, False),
     (set(), False)])
def test_get_network_data(main_node, confirmations, result: bool, monkeypatch, app):
    session_mock = MagicMock()
    monkeypatch.setattr(app.logger, 'debug', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    confirmation_data = ConfirmationData(datetime.now(), main_node.url, main_node.info, main_node.my_certificate,
                                         confirmations)
    network_data = main_node.get_network_data(confirmation_data)
    cert_keys = list(main_node.node_certs.keys())
    if result:
        assert network_data.active_nodes == list(main_node.active_nodes)
        assert network_data.node_certs == [(cert_keys[0], convert_cert_to_str(main_node.node_certs.get(cert_keys[0]))),
                                           (cert_keys[1], convert_cert_to_str(main_node.node_certs.get(cert_keys[1]))),
                                           (cert_keys[2], convert_cert_to_str(main_node.node_certs.get(cert_keys[2]))),
                                           (cert_keys[3], convert_cert_to_str(main_node.node_certs.get(cert_keys[3])))]
        assert network_data.sender_url == main_node.url
        assert network_data.sender_hash == main_node.info.hash_name
        assert network_data.auth_transactions == main_node.auth_transaction_pool.get_trx_dict()
        assert network_data.auth_blocks == main_node.auth_blockchain.get_block_dict()
    else:
        assert network_data is None


@pytest.mark.parametrize(
    "add_trx, calls",
    [(False, 4),
     (True, 3)
     ])
def test_init_network_data(main_node, monkeypatch, app, sender_node, calls, add_trx):
    session_mock = MagicMock()
    monkeypatch.setattr(session, "add_all", session_mock)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "query", Query)
    monkeypatch.setattr(Query, "first", lambda *args, **kwargs: None)
    monkeypatch.setattr(app.logger, 'debug', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    confirmation_data = ConfirmationData(datetime.now(), main_node.url, main_node.info, main_node.my_certificate,
                                         {(True, '')})
    network_data = main_node.get_network_data(confirmation_data)
    sender_node.init_network_data(network_data)
    assert len(session_mock.call_args_list[1].args[0]) == 4
    assert len(sender_node.auth_transaction_pool.transactions) == len(main_node.auth_transaction_pool.transactions)
    assert sender_node.auth_transaction_pool == main_node.auth_transaction_pool
    assert sender_node.auth_blockchain == main_node.auth_blockchain


@pytest.mark.parametrize(
    "confirmations, hash_name, result",
    [({(True, ''), (True, ''), (True, '')}, 'new_hash', True),
     ({(True, ''), (True, ''), (True, '')}, 'asdfqwe55', False),
     ({(True, ''), (False, ''), (True, '')}, 'new_hash', False),
     (set(), 'new_hash', False)])
def test_register_node(main_node, app, monkeypatch, confirmations, result, hash_name):
    device = DeviceIdentifier("", "", "", "")
    monkeypatch.setattr(device, 'hash_name', hash_name)
    monkeypatch.setattr(app.logger, 'warning', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)

    confirmation_data = ConfirmationData(datetime.now(), "new_url", device, main_node.my_certificate,
                                         confirmations)
    registered = main_node.register_another_node(confirmation_data)
    if result:
        assert ("new_url", hash_name) in main_node.active_nodes
        assert main_node.node_certs.get(hash_name) is not None
        assert isinstance(main_node.node_certs.get(hash_name), CustomCertificate)
        assert registered == result
    else:
        assert ("new_url", main_node.my_certificate) not in main_node.active_nodes
        assert registered == result


@pytest.mark.parametrize(
    "confirmations, hash_name, result",
    [({(True, ''), (True, ''), (True, '')}, 'new_hash', False),
     ({(True, ''), (True, ''), (True, '')}, 'asdfqwe55', True),
     ({(True, ''), (False, ''), (True, '')}, 'new_hash', False)])
def test_login_node(main_node, app, monkeypatch, confirmations, result, hash_name):
    device = DeviceIdentifier("", "", "", "")
    monkeypatch.setattr(device, 'hash_name', hash_name)
    monkeypatch.setattr(app.logger, 'warning', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)

    confirmation_data = ConfirmationData(datetime.now(), "new_url", device, main_node.my_certificate,
                                         confirmations)
    registered = main_node.login_another_node(confirmation_data)
    if result:
        assert ("new_url", hash_name) in main_node.active_nodes
        assert main_node.node_certs.get(hash_name) is not None
        assert isinstance(main_node.node_certs.get(hash_name), CustomCertificate)
        assert registered == result
    else:
        assert ("new_url", main_node.my_certificate) not in main_node.active_nodes
        assert registered == result


def test_logout_node(main_node, monkeypatch, app):
    monkeypatch.setattr(app.logger, 'warning', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    id = DeviceIdentifier("PC1", 'mac_address', 'serial_nb', 'model')
    node_url = 'logout_url'
    main_node.active_nodes.add((node_url, id.hash_name))

    logout = (main_node.logout_another_node('other_url', id))
    assert not logout
    assert (node_url, id.hash_name) in main_node.active_nodes
    assert node_url in main_node.get_url_nodes()

    logout = main_node.logout_another_node(node_url, id)
    assert logout

def test_get_nodes(main_node):
    active_nodes = main_node.active_nodes

    assert (main_node.url, main_node.info.hash_name) not in active_nodes
    all_active_nodes = main_node.get_network_nodes()

    assert (main_node.url, main_node.info.hash_name) in all_active_nodes
