from sqlalchemy import Column, String

from model.db import Transaction


class AuthTransaction(Transaction):
    __tablename__ = "AuthTransactions"
    action_type = Column("action", String)
