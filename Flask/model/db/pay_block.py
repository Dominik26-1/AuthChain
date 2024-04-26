from datetime import date

from model.db import Block


class PaymentBlock(Block):
    __tablename__ = "PaymentBlocks"


class GenesisPaymentBlock(PaymentBlock):
    def __init__(self):
        super().__init__(0, date(2023, 12, 24), "", '0', 0, "")
