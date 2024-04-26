import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from model.json.base import BasePayload


@dataclass
class JSONPayload(BasePayload):
    action_name: str
    signature: str = ''

    def sign_payload(self, private_key: PrivateKeyTypes):
        from certificate.cert_verifier import sign_text
        self.signature = sign_text(private_key, self.get_fingerprint())

    def get_fingerprint(self) -> str:
        dict_to_serialize = self.to_dict()
        del dict_to_serialize['signature']
        return json.dumps(dict_to_serialize, sort_keys=True)
