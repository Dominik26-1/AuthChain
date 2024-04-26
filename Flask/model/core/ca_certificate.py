from cryptography.x509 import Certificate

from model.core.certificate import CustomCertificate


class CACustomCertificate(CustomCertificate):

    def to_dict(self) -> dict[str, any]:
        result_map: dict[str, any] = {"certificate_number": self.cert.serial_number,
                                      "issuer": self.cert.issuer,
                                      "not_valid_after": self.cert.not_valid_after,
                                      "not_valid_before": self.cert.not_valid_before}
        return result_map
