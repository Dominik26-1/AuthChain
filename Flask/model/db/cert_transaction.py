from sqlalchemy import Column, String

from model.db import Transaction


class CertificateTransaction(Transaction):
    __tablename__ = "CertTransaction"
    certificate = Column("certificate", String)
