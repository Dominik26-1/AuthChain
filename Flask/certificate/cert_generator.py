import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from certificate.cert_convertor import convert_bytes_to_cert
from certificate.cert_loader import load_certificate, load_private_key
from config import Config
from constants import MAC_ADDRESS_OID, MODEL_OID, SERIAL_NUMBER_OID, VALID_CERTIFICATE_DAYS
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier


def __sign_csr(csr_pem: bytes, ca_cert: CustomCertificate, ca_private_key: RSAPrivateKey) -> bytes:
    # Load CSR
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Sign the CSR with CA's private key
    cert = (x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=VALID_CERTIFICATE_DAYS)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        csr.extensions.get_extension_for_oid(ObjectIdentifier(MAC_ADDRESS_OID)).value, critical=True
    ).add_extension(
        csr.extensions.get_extension_for_oid(ObjectIdentifier(SERIAL_NUMBER_OID)).value, critical=True
    ).add_extension(
        csr.extensions.get_extension_for_oid(ObjectIdentifier(MODEL_OID)).value, critical=True
    ).sign(ca_private_key, hashes.SHA256(), default_backend()))


    # Serialize the signed certificate
    signed_cert = cert.public_bytes(serialization.Encoding.PEM)

    return signed_cert


def __create_csr(device_info: DeviceIdentifier) -> (bytes, RSAPrivateKey):
    # Vytvorenie kľúčového páru
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SK"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kosice"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Technical University of Kosice"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "FEI"),
        x509.NameAttribute(NameOID.COMMON_NAME, device_info.common_name)
    ])

    hash_mac, hash_serial_nb, hash_model = device_info.hash_identifier()

    # Create a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject
                                                               ).add_extension(
        x509.UnrecognizedExtension(ObjectIdentifier(MAC_ADDRESS_OID), hash_mac.encode()),
        critical=True
    ).add_extension(
        x509.UnrecognizedExtension(ObjectIdentifier(SERIAL_NUMBER_OID), hash_serial_nb.encode()),
        critical=True
    ).add_extension(
        x509.UnrecognizedExtension(ObjectIdentifier(MODEL_OID), hash_model.encode()),
        critical=True
    ).sign(key, hashes.SHA256(), default_backend())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return csr_pem, key


def generate_certificate(device_id: DeviceIdentifier) -> (CustomCertificate, RSAPrivateKey):
    # Vytvorenie certifikátu
    csr_bytes, private_key = __create_csr(device_id)

    ca_cert = load_certificate("fullchain.pem", Config.CERT_FOLDER_PATH)
    ca_private_key = load_private_key("privkey.pem", Config.CERT_FOLDER_PATH)
    cert_bytes = __sign_csr(csr_bytes, ca_cert, ca_private_key)

    cert = convert_bytes_to_cert(cert_bytes)
    return cert, private_key
