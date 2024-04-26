from datetime import date

from model.db import Block


class AuthBlock(Block):
    __tablename__ = "AuthBlocks"


class GenesisAuthBlock(AuthBlock):
    def __init__(self):
        super().__init__(0, date(2023, 12, 24), "", '0', 0, "")
