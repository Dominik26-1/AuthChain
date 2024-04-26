from operator import attrgetter

from flask import current_app, flash

from constants import TRANSACTION_THRESHOLD
from enumeration import ErrorCategory
from model.chain.blockchain import Blockchain
from model.chain.transaction_pool import TransactionPool
from model.db import Block
from utils.string_utils import serialize_transactions



def verify_block(previous_block: Block, verifying_block: Block) -> bool:
    if previous_block.index + 1 != verifying_block.index:
        current_app.logger.error(
            f'Index in new-created block does not continue with previous block. Previous: {previous_block.index}, actual: {verifying_block.index}')
        flash(f"Index in new-created block does not continue with previous block.", ErrorCategory.WARNING.value)
        return False

    if previous_block.block_hash != verifying_block.previous_hash:
        current_app.logger.error(
            f'Hash of previous block does not matched with the same one in new-created block. Previous: {previous_block.block_hash}, actual: {verifying_block.previous_hash}')
        flash(f"Hash of previous block does not matched with the same one in new-created block.",
              ErrorCategory.WARNING.value)
        return False

    if verifying_block.block_hash != verifying_block.create_hash():
        current_app.logger.error(
            f"Integrity of block was not successfully verified. Hashes not match. {verifying_block.block_hash} vs {verifying_block.create_hash()}")

        flash(f"Integrity of block was not successfully verified",
              ErrorCategory.WARNING.value)
        return False
    return True


def verify_new_block(blockchain: Blockchain, incoming_block: Block, transaction_pool: TransactionPool) -> bool:
    latest_block = blockchain.get_latest_block()

    block_verified = verify_block(latest_block, incoming_block)
    if not block_verified:
        return False

    expected_block_trx = transaction_pool.get_block_trx()
    transaction_string = serialize_transactions(expected_block_trx)
    if incoming_block.data != transaction_string:
        current_app.logger.error(
            f'Transaction data in new-created block not matched latest transactions: {transaction_string} against Block_data:{incoming_block.data}')
        flash(f"Transaction data in new-created block not matched latest transactions.", ErrorCategory.ERROR.value)
        return False
    return True
