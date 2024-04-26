import hashlib

from model.common.common import SerializableModel
from utils.hash_utils import hash_text


class DeviceIdentifier(SerializableModel):

    def __init__(self, common_name: str, serial_number: str, mac_address: str, model: str):
        self.common_name = common_name
        self.serial_number = serial_number
        self.mac_address = mac_address
        self.model = model
        self.hash_name = self.__create_hash()

    def __create_hash(self) -> str:
        # Vytvoření block_hash pomocí SHA-256
        combined_string = self.serial_number + self.mac_address + self.model
        hash_object = hashlib.sha256(combined_string.encode())
        return hash_object.hexdigest()

    def hash_identifier(self) -> (str, str, str):
        return hash_text(self.mac_address), hash_text(self.serial_number), hash_text(self.model)
