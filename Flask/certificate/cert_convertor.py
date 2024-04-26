from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from flask import current_app

from model.core.ca_certificate import CACustomCertificate
from model.core.certificate import CustomCertificate


def convert_bytes_to_cert(pem_data: bytes, is_cert_authority=False) -> CustomCertificate:
    try:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    except ValueError as e:
        current_app.logger.error("Incorrect input bytes of pem certificate.", e)
        raise e
    if is_cert_authority:
        return CACustomCertificate(cert)
    else:
        return CustomCertificate(cert)


def convert_str_to_cert(pem_data: str) -> CustomCertificate:
    cert_bytes = pem_data.encode('utf-8')
    return convert_bytes_to_cert(cert_bytes)


def convert_cert_to_bytes(cert: CustomCertificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def convert_cert_to_str(cert: CustomCertificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def convert_str_to_key(key_str: str) -> PrivateKeyTypes:
    key_bytes = key_str.encode('utf-8')
    private_key = convert_bytes_to_key(key_bytes)
    return private_key


def convert_bytes_to_key(key_str: bytes) -> PrivateKeyTypes:
    private_key = serialization.load_pem_private_key(
        key_str,
        password=None,
        backend=default_backend()
    )
    return private_key


def convert_key_to_bytes(key: PrivateKeyTypes) -> bytes:
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key
