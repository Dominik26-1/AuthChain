from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from flask import current_app, flash

from certificate.cert_convertor import convert_cert_to_bytes, convert_key_to_bytes
from enumeration import ErrorCategory
from model.core.certificate import CustomCertificate

'''def save_certificate(file: FileStorage, file_name: str):
    # Tu môžete súbor uložiť alebo spracovať
    file.save(Config.CERT_FOLDER_PATH + file_name)
    '''


def save_certificate(cert: CustomCertificate, folder_path: str, file_name: str):
    cert_bytes = convert_cert_to_bytes(cert)
    save_certificate_bytes(cert_bytes, folder_path, file_name)


def save_certificate_bytes(cert_bytes: bytes, folder_path: str, file_name: str):
    cert_bytes_written = 0
    try:
        with open(folder_path + file_name, "wb") as cert_file:
            cert_bytes_written = cert_file.write(cert_bytes)
    except Exception as e:
        flash(f"Certificate was not saved into {folder_path + file_name}.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f'Certificate was not saved into {folder_path + file_name} with error {e}.')
        return

    # Overenie, či počet zapísaných bajtov zodpovedá dĺžke dát
    if cert_bytes_written != len(cert_bytes):
        flash("No bytes was save as a certificate.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f'No bytes was save as a certificate into {folder_path + file_name}.')


def save_private_key(private_key: PrivateKeyTypes, folder_path: str, file_name: str):
    key_bytes_written = 0
    private_key_bytes: bytes = convert_key_to_bytes(private_key)
    save_private_key_bytes(private_key_bytes, folder_path, file_name)


def save_private_key_bytes(private_key_bytes: bytes, folder_path: str, file_name: str):
    key_bytes_written = 0
    try:
        with open(folder_path + file_name, "wb") as key_file:
            key_bytes_written = key_file.write(private_key_bytes)
    except Exception as e:
        flash(f"Private key was not saved into {folder_path + file_name}.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f'Private key was not saved into {folder_path + file_name} with error {e}.')
        return

    if key_bytes_written != len(private_key_bytes):
        flash("No bytes was save as a private key.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f'No bytes was save as a private key into {folder_path + file_name}.')
