from constants import TRANSACTION_THRESHOLD
from model.db import Transaction


class TransactionPool:
    transactions: list[Transaction]

    def __init__(self, transactions: list[Transaction]):
        self.transactions = transactions

    def add(self, transaction: Transaction):
        self.transactions.append(transaction)

    def remove(self, transaction: Transaction):
        self.transactions.remove(transaction)

    def update(self, transactions: list[Transaction]):
        self.transactions.extend(transactions)

    def clear(self):
        self.transactions = []

    def get_block_trx(self) -> list[Transaction]:
        return sorted(self.transactions, key=lambda trx: (trx.creation_timestamp, trx.id))[:TRANSACTION_THRESHOLD]

    def clear_block_trx(self):
        block_trx = sorted(self.transactions, key=lambda trx: (trx.creation_timestamp, trx.id))[:TRANSACTION_THRESHOLD]
        for trx in block_trx:
            if trx in self.transactions:
                self.transactions.remove(trx)

    def get_trx_dict(self) -> list[dict]:
        self.transactions.sort(key=lambda trx: (trx.creation_timestamp, trx.id))
        return list(map(lambda t: t.to_dict(), self.transactions))

    def get_node_trx(self, node_id: str) -> list[Transaction]:
        node_trx: list[Transaction] = list(filter(lambda trx: trx.node_id == node_id, self.transactions.copy()))
        node_trx.sort(key=lambda trx: (trx.creation_timestamp, trx.id), reverse=True)
        return node_trx

    def get_block_creator_id(self) -> str:
        self.transactions.sort(key=lambda trx: (trx.creation_timestamp, trx.id))
        return self.transactions[TRANSACTION_THRESHOLD - 1].node_id

    def __eq__(self, other):
        return isinstance(other, TransactionPool) and self.transactions == other.transactions
