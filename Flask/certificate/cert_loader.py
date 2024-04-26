from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certificate.cert_convertor import convert_bytes_to_cert, convert_bytes_to_key
from config import Config
from model.core.ca_certificate import CACustomCertificate
from model.core.certificate import CustomCertificate


def load_certificate(file_name, folder_path, is_CA: bool = False) -> CustomCertificate | CACustomCertificate | None:
    try:
        with open(folder_path + file_name, 'rb') as file:
            pem_data = file.read()
            return convert_bytes_to_cert(pem_data, is_CA)
    except FileNotFoundError:
        # Súbor nebol nájdený, vráti None
        return None


def load_private_key(file_name, folder_path) -> PrivateKeyTypes | None:
    try:
        with open(folder_path + file_name, 'rb') as key_file:
            return convert_bytes_to_key(key_file.read())
    except FileNotFoundError:
        # Súbor nebol nájdený, vráti None
        return None


def load_cert_for_request(file_name: str):
    file_path = Config.CERT_FOLDER_PATH + file_name
    with open(file_path, 'rb') as file:
        return (file_path, file, 'application/x-x509-ca-cert')
