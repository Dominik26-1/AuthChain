from sqlalchemy import Column, Float

from model.db import Transaction


class PaymentTransaction(Transaction):
    __tablename__ = "PaymentTransaction"
    price = Column("price", Float)
