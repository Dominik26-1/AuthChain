import base64
import datetime

from OpenSSL import crypto
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import flash, current_app

from constants import MAC_ADDRESS_OID, SERIAL_NUMBER_OID, MODEL_OID
from enumeration import ErrorCategory
from model.core.ca_certificate import CACustomCertificate
from model.core.certificate import CustomCertificate
from model.device import DeviceIdentifier
from utils.hash_utils import hash_text


def sign_text(private_key, text: str) -> str:
    # Vráti block_hash ako hexadecimálny reťazec
    hash_str = hash_text(text)

    signed_bytes = private_key.sign(
        hash_str.encode("UTF-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # Encode the signature in base64
    return base64.b64encode(signed_bytes).decode("UTF-8")


def verify_text(cert: CustomCertificate, signature: str, plain_text: str) -> bool:
    plain_hash = hash_text(plain_text)
    # Verifikácia podpisu pomocou verejného kľúča (z certifikátu)
    expected_bytes = plain_hash.encode('utf-8')
    signature_bytes = base64.b64decode(signature)
    public_key = cert.public_key()

    try:
        public_key.verify(
            signature_bytes,
            expected_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        flash(f"Error with integration of data: signature verification failed.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f"Error with integration of data: signature verification failed. {signature}")
        # Verifikácia zlyhala
        return False


def verify_cert(cert: CustomCertificate, ca_cert: CACustomCertificate, device_metadata: DeviceIdentifier) -> bool:
    conditions = []

    mac_address: str = cert.extensions.get_extension_for_oid(
        ObjectIdentifier(MAC_ADDRESS_OID)).value.value.decode()
    serial_number: str = cert.extensions.get_extension_for_oid(
        ObjectIdentifier(SERIAL_NUMBER_OID)).value.value.decode()
    model: str = cert.extensions.get_extension_for_oid(ObjectIdentifier(MODEL_OID)).value.value.decode()
    common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    hashed_mac_address, hashed_serial_nb, hashed_model = device_metadata.hash_identifier()
    conditions.append(mac_address == hashed_mac_address)
    conditions.append(serial_number == hashed_serial_nb)
    conditions.append(model == hashed_model)
    conditions.append(common_name == device_metadata.common_name)

    conditions.append(cert.not_valid_before < datetime.datetime.now())
    conditions.append(cert.not_valid_after > datetime.datetime.now())

    ca_pem_cert = ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    pem_cert = ca_cert.public_bytes(encoding=serialization.Encoding.PEM)

    # Konverzia na pyOpenSSL formát
    ca_openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem_cert)
    openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
    store = crypto.X509Store()
    store.add_cert(ca_openssl_cert)
    store_ctx = crypto.X509StoreContext(store, openssl_cert)

    try:
        store_ctx.verify_certificate()
        # conditions.append(True)
    except crypto.X509StoreContextError:
        # conditions.append(False)
        pass
    return all(conditions)
