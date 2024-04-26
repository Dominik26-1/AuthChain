from dataclasses import dataclass
from typing import Type

from model.common import SerializableModel
from model.db import Transaction, Block
from model.db.auth_block import AuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.cert_block import CertificateBlock
from model.db.cert_transaction import CertificateTransaction
from model.db.pay_transaction import PaymentTransaction
from model.json import NodeData


@dataclass
class BlockchainData(NodeData):
    auth_transactions: list[dict]
    auth_blocks: list[dict]
    pay_transactions: list[dict]
    pay_blocks: list[dict]
    cert_transactions: list[dict]
    cert_blocks: list[dict]

    def get_transactions(self, type: type[Transaction]) -> list[Transaction]:
        trx_list = []

        if type is AuthTransaction:
            for trx_dict in self.auth_transactions:
                trx_list.append(type.from_dict(trx_dict))
        elif type is CertificateTransaction:
            for trx_dict in self.cert_transactions:
                trx_list.append(type.from_dict(trx_dict))
        else:
            for trx_dict in self.pay_transactions:
                trx_list.append(type.from_dict(trx_dict))

        return trx_list

    def get_blocks(self, type: Type[Block]) -> list[Block]:
        block_list = []
        if type is AuthBlock:
            blocks = self.auth_blocks
        elif type is CertificateBlock:
            blocks = self.cert_blocks
        else:
            blocks = self.pay_blocks

        for block_dict in blocks:
            block_list.append(type.from_dict(block_dict, calculated_attrs=['block_hash']))
        return block_list
