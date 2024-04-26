import random
from datetime import datetime

from model.db import Transaction, Block
from model.db.auth_block import AuthBlock, GenesisAuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.cert_block import CertificateBlock, GenesisCertificateBlock
from model.db.cert_transaction import CertificateTransaction
from model.db.pay_block import GenesisPaymentBlock, PaymentBlock
from model.db.pay_transaction import PaymentTransaction
from utils.string_utils import deserialize_transactions


class Blockchain:

    def __init__(self, genesisBlock: Block, blockchain_type: type[Block]):
        self.blocks: list[Block] = []
        self.blocks.append(genesisBlock)
        self.block_type: type[Block] = blockchain_type
        if blockchain_type is AuthBlock:
            self.trx_type = AuthTransaction
        elif blockchain_type is CertificateBlock:
            self.trx_type = CertificateTransaction
        elif blockchain_type is PaymentBlock:
            self.trx_type = PaymentTransaction
        else:
            self.trx_type = None

    def add(self, block: Block):
        self.blocks.append(block)

    def get_block_dict(self) -> list[dict]:
        return list(map(lambda b: b.to_dict(), self.blocks))

    def get_latest_block(self) -> Block:
        return self.blocks[len(self.blocks) - 1]

    def get_trx(self, number: int = None) -> list[Transaction]:
        transactions: list[Transaction] = []
        for block in sorted(self.blocks, key=lambda b: b.index, reverse=True):
            transactions.extend(deserialize_transactions(block.data, self.trx_type))
            if number is not None and len(transactions) >= number:
                break

        transactions.sort(key=lambda trx: trx.creation_timestamp, reverse=True)
        return transactions

    def get_node_trx(self, node_id: str) -> list[Transaction]:
        transactions: list[Transaction] = []
        node_blocks: list[Block] = list(filter(lambda b: b.node_id == node_id, self.blocks))
        for block in sorted(node_blocks, key=lambda b: b.index, reverse=True):
            transactions.extend(deserialize_transactions(block.data, self.trx_type))
        transactions.sort(key=lambda trx: trx.creation_timestamp, reverse=True)
        return transactions

    def get_blockchain_node_score(self, pool_transaction: list[Transaction], node_id: str,
                                  registration_time: datetime) -> float:
        from enumeration import Action
        all_trx: list[Transaction] = self.get_trx() + pool_transaction
        node_trx = list(filter(lambda trx: trx.node_id == node_id, all_trx))

        device_age = (datetime.now() - registration_time).days * 0.1
        random_number = random.uniform(0.0001, 0.1)
        return (len(node_trx) / len(all_trx)) * 1000000 + device_age + random_number

    def verify_blockchain(self) -> bool:
        from chain import verify_block
        for previous_block, next_block in zip(self.blocks, self.blocks[1:]):
            if not verify_block(previous_block, next_block):
                return False
        return True

    def get_blockchain_length(self) -> float:
        return sum(block.weight for block in self.blocks)

    def __eq__(self, other):
        return isinstance(other, Blockchain) and self.blocks == other.blocks

    @classmethod
    def create(cls, blocks: list[Block]):
        if len(blocks) != 0 and isinstance(blocks[0], AuthBlock):
            genesis_block = GenesisAuthBlock()
            block_type = AuthBlock
        elif len(blocks) != 0 and isinstance(blocks[0], CertificateBlock):
            genesis_block = GenesisCertificateBlock()
            block_type = CertificateBlock
        else:
            genesis_block = GenesisPaymentBlock()
            block_type = PaymentBlock
        blockchain = Blockchain(genesis_block, block_type)
        blockchain.blocks = blocks.copy()
        return blockchain
