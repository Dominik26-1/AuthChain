from cryptography import x509
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.x509 import Certificate

from constants import MAC_ADDRESS_OID, SERIAL_NUMBER_OID, MODEL_OID


class CustomCertificate:
    def __init__(self, cert: Certificate):
        self.cert = cert

    def to_dict(self) -> dict[str, any]:
        result_map: dict[str, any] = {"mac_address": self.cert.extensions.get_extension_for_oid(
            ObjectIdentifier(MAC_ADDRESS_OID)).value.value.decode(),
                                      "serial_number": self.cert.extensions.get_extension_for_oid(
                                          ObjectIdentifier(SERIAL_NUMBER_OID)).value.value.decode(),
                                      "model": self.cert.extensions.get_extension_for_oid(
                                          ObjectIdentifier(MODEL_OID)).value.value.decode(),
                                      "common_name": self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                                          0].value,
                                      "certificate_number": self.cert.serial_number,
                                      "issuer": self.cert.issuer,
                                      "not_valid_after": self.cert.not_valid_after,
                                      "not_valid_before": self.cert.not_valid_before}
        return result_map

    def __getattr__(self, name):
        return getattr(self.cert, name)
