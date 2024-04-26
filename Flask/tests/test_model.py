from datetime import datetime

from model.db.auth_block import AuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.pay_block import PaymentBlock
from model.json import JSONPayload


def test_from_dict():
    trx = AuthTransaction(id="info", creation_timestamp=datetime.now(), action_type="LOGIN",
                          node_id='hash_name', node_url="url", node_name="name1")
    trx_dict = trx.to_dict()
    assert trx == AuthTransaction.from_dict(trx_dict)

    jp = JSONPayload(timestamp=datetime.now().isoformat(), node_url='sender_url',
                     node_id={},
                     action_name="SIGNUP", cert_string='aaaaaaa')
    jp_dict = jp.to_dict()
    final_jp = JSONPayload.from_dict(jp_dict)
    timestamp = final_jp.timestamp
    assert jp != final_jp
    assert isinstance(timestamp, datetime)

    final_jp = JSONPayload.from_dict(jp_dict, False)
    assert jp == final_jp


def test_block_from(main_node):
    block = main_node.create_block(main_node.auth_transaction_pool.get_block_trx())
    block_dict = block.to_dict()
    new_block = AuthBlock.from_dict(block_dict, calculated_attrs=['block_hash'])
    assert block == new_block
    assert block.data == new_block.data

    block = main_node.create_block(main_node.pay_transaction_pool.get_block_trx())
    block_dict = block.to_dict()
    new_block = PaymentBlock.from_dict(block_dict, calculated_attrs=['block_hash'])
    assert block == new_block
    assert block.data == new_block.data