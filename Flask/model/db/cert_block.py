from datetime import date

from model.db import Block


class CertificateBlock(Block):
    __tablename__ = "CertBlocks"


class GenesisCertificateBlock(CertificateBlock):
    def __init__(self):
        super().__init__(0, date(2023, 12, 24), "", '0', 0, "")
