from model.chain import TransactionPool
from model.chain.blockchain import Blockchain
from model.db import Transaction


def get_trx(blockchain: Blockchain, trx_pool: TransactionPool) -> list[Transaction]:
    block_trx: list[Transaction] = blockchain.get_trx()
    trx_pool: list[Transaction] = trx_pool.transactions

    all_trx: list[Transaction] = sorted((block_trx + trx_pool), key=lambda trx: trx.creation_timestamp,
                                        reverse=True)
    return all_trx
