from cryptography.hazmat.primitives import hashes

from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier


def verify_signup(actual_cert: CustomCertificate, existing_cert: CustomCertificate | None, device_id: DeviceIdentifier) -> bool:
    return existing_cert is None

def verify_login(actual_cert: CustomCertificate, existing_cert: CustomCertificate | None, device_id: DeviceIdentifier) -> bool:
    return existing_cert is not None and existing_cert.fingerprint(
        hashes.SHA256()) == actual_cert.fingerprint(hashes.SHA256())


def verify_update(actual_cert: CustomCertificate, existing_cert: CustomCertificate | None, device_id: DeviceIdentifier) -> bool:
    return existing_cert is not None


def verify_logout(actual_cert: CustomCertificate, existing_cert: CustomCertificate | None, device_id: DeviceIdentifier) -> bool:
    return True
