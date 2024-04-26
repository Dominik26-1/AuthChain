import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
import requests

from chain import verify_new_block
from db import session
from enumeration import Action
from model.db import Transaction, Block
from model.db.auth_transaction import AuthTransaction
from model.db.pay_transaction import PaymentTransaction
from utils.string_utils import serialize_transactions, deserialize_transactions


def test_data_serialization(main_node):
    original_trx = [
        AuthTransaction(id=uuid.uuid4().hex, creation_timestamp=datetime.now(), action_type="LOGIN",
                        node_id="node1", node_url="node_url1", node_name="name1"),
        AuthTransaction(id=uuid.uuid4().hex, creation_timestamp=datetime.now() + timedelta(0, 1),
                        action_type="LOGIN",
                        node_id="node2", node_url="node_url2", node_name="name1"),
        AuthTransaction(id=uuid.uuid4().hex, creation_timestamp=datetime.now() + timedelta(0, 2),
                        action_type="LOGOUT",
                        node_id="node2", node_url="node_url2", node_name="name1"),
        AuthTransaction(id=uuid.uuid4().hex, creation_timestamp=datetime.now() + timedelta(0, 3),
                        action_type="LOGOUT",
                        node_id="node2", node_url="node_url3", node_name="name1"),
    ]
    for trx in original_trx:
        trx.sign_transaction(main_node.my_private_key)
    trx_str = serialize_transactions(original_trx)
    trx_list = deserialize_transactions(trx_str, AuthTransaction)

    assert len(original_trx) == len(trx_list)
    assert original_trx == trx_list


def test_generate_5th_auth_trx(main_node, monkeypatch):
    # Použitie MonkeyPatch na nahradenie broadcast_request metódou mock_broadcast_request
    monkeypatch.setattr(main_node, "broadcast_request", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)

    main_node.generate_trx(AuthTransaction, action_type=Action.LOGOUT.name)
    assert len(main_node.auth_blockchain.blocks) == 2
    genesis_block = main_node.auth_blockchain.blocks[0]
    created_block = main_node.auth_blockchain.blocks[1]

    assert created_block.index == 1
    assert created_block.previous_hash == genesis_block.block_hash
    trx_list = deserialize_transactions(created_block.data, AuthTransaction)
    assert isinstance(trx_list, list)
    assert len(trx_list) == 5
    assert main_node.auth_transaction_pool.transactions == []


def test_generate_5th_pay_trx(main_node, monkeypatch):
    # Použitie MonkeyPatch na nahradenie broadcast_request metódou mock_broadcast_request
    monkeypatch.setattr(main_node, "broadcast_request", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)

    main_node.generate_trx(PaymentTransaction, price=1000)
    assert len(main_node.pay_blockchain.blocks) == 2
    genesis_block = main_node.pay_blockchain.blocks[0]
    created_block = main_node.pay_blockchain.blocks[1]

    assert created_block.index == 1
    assert created_block.previous_hash == genesis_block.block_hash
    trx_list = deserialize_transactions(created_block.data, AuthTransaction)
    assert isinstance(trx_list, list)
    assert len(trx_list) == 5
    assert main_node.pay_transaction_pool.transactions == []


@pytest.mark.parametrize(
    "index, data, result",
    [(1, [], True),
     (1, [Transaction(id="info", creation_timestamp=datetime.now(),
                      node_id="block_hash", node_name="name", node_url="url")], False),
     (2, [], False)])
def test_verify_block(main_node, index: int, data: list[Transaction], result: bool, monkeypatch, app):
    monkeypatch.setattr(app.logger, 'error', lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    main_node.auth_transaction_pool.add(main_node.create_transaction(AuthTransaction, action_type=Action.LOGOUT.name))

    for trx in data:
        main_node.auth_transaction_pool.add(trx)
    data_str = serialize_transactions(main_node.auth_transaction_pool.transactions)
    block = Block(index=index, creation_timestamp=datetime.now(),
                  data=data_str,
                  previous_hash='7de76c937720b4299a8e532de146bd3955e1a9710f4e8dc6525286af3cc66107', weight=0,
                  node_id='')
    verification = verify_new_block(main_node.auth_blockchain, block, main_node.auth_transaction_pool)
    assert verification is result


def test_send_heartbeat(main_node, monkeypatch, app):
    # Funkcia, ktorá vráti rôzne mockované odpovede v závislosti od URL
    def requests_get_return_value(url):
        if url == 'https://10.126.147.18:8443/api':
            raise RecursionError
        else:
            return MagicMock(status_code=200)

    mock_post_request = MagicMock()
    monkeypatch.setattr(requests, 'get', requests_get_return_value)
    monkeypatch.setattr(requests, 'post', mock_post_request)

    assert "https://10.126.147.18:8443/api" in main_node.get_url_nodes()
    main_node._NodeSender__send_heartbeat()
    assert len(main_node.active_nodes) == 2
    assert "https://10.126.147.18:8443/api" not in main_node.get_url_nodes()

    expected_post_call_count = 2
    assert mock_post_request.called
    assert mock_post_request.call_count == expected_post_call_count


def test_verifying_trx(main_node, app, monkeypatch):
    mock_logger = MagicMock()
    monkeypatch.setattr(app.logger, 'warning', mock_logger)
    monkeypatch.setattr(app.logger, 'error', lambda *args, **kwargs: None)
    monkeypatch.setattr(main_node, "broadcast_request", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    main_node.auth_transaction_pool.clear()
    trx = AuthTransaction(id="info", creation_timestamp=datetime.now(), action_type="LOGIN",
                          node_id=main_node.info.hash_name, node_url="url", node_name="name1")

    trx.sign_transaction(main_node.my_private_key)
    main_node.handle_transaction(trx)

    mock_logger.assert_not_called()
    assert trx in main_node.auth_transaction_pool.transactions

    main_node.auth_transaction_pool.clear()
    trx.node_url = "new_url"

    main_node.handle_transaction(trx)

    mock_logger.assert_called()
    assert trx not in main_node.auth_transaction_pool.transactions


def test_trigger_block_creation(main_node, monkeypatch):
    trx = main_node.create_transaction(AuthTransaction, action_type=Action.LOGOUT.name)
    mock_broadcast = MagicMock()
    monkeypatch.setattr(main_node, 'broadcast_request', mock_broadcast)
    old_trx = main_node.auth_transaction_pool.transactions.copy()
    old_trx.append(trx)
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    main_node.store_transaction(trx)

    assert len(main_node.auth_blockchain.blocks) == 2
    new_block = main_node.auth_blockchain.get_latest_block()
    assert new_block.index == 1
    assert new_block.previous_hash == main_node.auth_blockchain.blocks[0].block_hash
    trx_data = serialize_transactions(old_trx)
    assert new_block.data == trx_data
    mock_broadcast.assert_called()


def test_receive_block(monkeypatch, main_node):
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: None)
    block = main_node.create_block(main_node.auth_transaction_pool.transactions)
    main_node.receive_block(block)
    assert len(main_node.auth_blockchain.blocks) == 2
    assert main_node.auth_blockchain.get_latest_block() == block


def test_get_node_trx(monkeypatch, main_node, sender_node):
    monkeypatch.setattr(session, "add", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "commit", lambda *args, **kwargs: None)
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: None)
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: None)
    main_node.store_transaction(main_node.create_transaction(AuthTransaction, action_type=Action.LOGOUT.name))
    main_node.store_transaction(main_node.create_transaction(AuthTransaction, action_type=Action.LOGIN.name))
    main_node.store_transaction(main_node.create_transaction(AuthTransaction, action_type=Action.LOGIN.name))

    auth_block_trx = main_node.auth_blockchain.get_node_trx(main_node.info.hash_name)
    auth_pool_trx = main_node.auth_transaction_pool.get_node_trx(main_node.info.hash_name)
    assert len(auth_block_trx) == 5
    assert len(auth_pool_trx) == 2

    main_node.store_transaction(main_node.create_transaction(PaymentTransaction, price=1547))
    main_node.store_transaction(sender_node.create_transaction(PaymentTransaction, price=654))
    main_node.store_transaction(main_node.create_transaction(PaymentTransaction, price=654))

    pay_block_trx = main_node.pay_blockchain.get_node_trx(main_node.info.hash_name)
    pay_pool_trx = main_node.pay_transaction_pool.get_node_trx(main_node.info.hash_name)
    assert len(pay_block_trx) == 5
    assert len(pay_pool_trx) == 1


