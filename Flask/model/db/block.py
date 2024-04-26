from datetime import date

from sqlalchemy import *

from model.common.common import SerializableDBModel
from utils.hash_utils import hash_text


class Block(SerializableDBModel):
    __abstract__ = True
    index = Column("index", Integer, primary_key=True)
    creation_timestamp = Column("timestamp", TIMESTAMP)
    data = Column("data", String)
    previous_hash = Column("previous_hash", String)
    block_hash = Column("block_hash", String)
    weight = Column("weight", Float)
    node_id = Column("node_id", String)

    def __repr__(self):
        return f'{self.index} ({self.data} {self.block_hash} ({self.previous_hash}))'

    def create_hash(self) -> str:
        return hash_text(
            f'{self.index}|{self.previous_hash}|{self.creation_timestamp}|{self.node_id}|{self.weight}{self.data}')

    def __init__(self, index: int, creation_timestamp, data: str, previous_hash: str, weight: float, node_id: str):
        self.index = index
        self.creation_timestamp = creation_timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.weight = weight
        self.node_id = node_id
        self.block_hash = self.create_hash()

    def __eq__(self, other):
        if isinstance(other, Block):
            return self.to_dict() == other.to_dict()
        return False


