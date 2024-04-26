import json
from datetime import datetime

from model.db import Transaction
from model.db.auth_transaction import AuthTransaction
from model.db.pay_transaction import PaymentTransaction


def deserialize_transactions(transaction_string: str) -> list[Transaction]:
    dict_list: list[dict] = json.loads(transaction_string)
    transactions: list[Transaction] = []
    for trx_dict in dict_list:
        transactions.append(Transaction.from_dict(trx_dict))
    transactions.sort(key=lambda trx: trx.creation_timestamp)
    return transactions


def serialize_transactions(transactions: list[Transaction]) -> str:
    # Convert the list of transaction dictionaries to a list of tuples
    tuple_list = [tuple(trx.to_dict().items()) for trx in transactions]

    # Create a set of tuples to remove duplicates
    unique_tuples = set(tuple_list)

    # Convert the set of tuples back to a list of dictionaries
    dict_list = [dict(tup) for tup in unique_tuples]

    # Sort `dict_list` by 'creation_date'
    sorted_dict_list = sorted(dict_list, key=lambda trx: trx['creation_timestamp'])
    # Return JSON dump of the list of dictionaries
    return json.dumps(sorted_dict_list)


def deserialize_transactions(transaction_string: str, trx_type: type[Transaction]) -> list[Transaction]:
    if transaction_string == '':
        return []
    dict_list: list[dict] = json.loads(transaction_string)
    transactions: list[Transaction] = []
    for trx_dict in dict_list:
        transactions.append(trx_type.from_dict(trx_dict))
    transactions.sort(key=lambda trx: trx.creation_timestamp)
    return transactions


def convert_iso_to_datetime(iso_str):
    try:
        return datetime.fromisoformat(iso_str)
    except ValueError:
        return iso_str
