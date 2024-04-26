import json

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from sqlalchemy import Column, String, TIMESTAMP

from model.common import SerializableDBModel


class Transaction(SerializableDBModel):
    __abstract__ = True

    id = Column("info", String, primary_key=True)
    creation_timestamp = Column("timestamp", TIMESTAMP)
    node_id = Column("node_id", String)
    node_name = Column("node_name", String)
    node_url = Column("node_url", String)
    signature = Column("signature", String)

    def __init__(self, **kwargs):
        self.signature = ""
        super().__init__(**kwargs)

    def sign_transaction(self, private_key: PrivateKeyTypes):
        from certificate.cert_verifier import sign_text
        self.signature = sign_text(private_key, self.serialize())

    def serialize(self) -> str:
        dict_to_serialize = self.to_dict()
        del dict_to_serialize['signature']
        return json.dumps(dict_to_serialize)

    def __repr__(self):
        return f"{self.id}: {self.__class__} {self.node_url} {self.creation_timestamp}"

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()
