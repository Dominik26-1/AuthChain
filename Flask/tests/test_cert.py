from unittest.mock import MagicMock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certificate.cert_convertor import convert_bytes_to_cert, convert_cert_to_bytes, convert_str_to_cert, \
    convert_cert_to_str
from certificate.cert_generator import generate_certificate
from certificate.cert_loader import load_certificate, load_private_key
from certificate.cert_saver import save_certificate, save_private_key
from certificate.cert_verifier import verify_cert
from config import Config
from model.core.certificate import CustomCertificate
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certificate.cert_convertor import convert_bytes_to_cert, convert_cert_to_bytes, convert_str_to_cert, \
    convert_cert_to_str
from certificate.cert_generator import generate_certificate
from certificate.cert_loader import load_certificate, load_private_key
from certificate.cert_saver import save_certificate, save_private_key
from certificate.cert_verifier import verify_cert
from config import Config
from model.core.certificate import CustomCertificate


def test_certificate_conversion(folder_test):
    original_cert = load_certificate('ca_cert.pem', folder_test)

    bytes = convert_cert_to_bytes(original_cert)
    new_cert_from_bytes = convert_bytes_to_cert(bytes)

    cert_string = convert_cert_to_str(original_cert)
    new_cert_from_str = convert_str_to_cert(cert_string)

    assert original_cert is not None
    assert vars(new_cert_from_bytes) == vars(original_cert)
    assert vars(new_cert_from_str) == vars(original_cert)


def test_certificate_not_found():
    original_cert = load_certificate('my_cert1.pem', Config.CERT_FOLDER_PATH)

    assert original_cert is None


def test_private_key_loading(folder_test):
    key = load_private_key('ca_private_key.key', folder_test)
    unexisting_key = load_private_key('unexisting_private.key', folder_test)

    assert isinstance(key, PrivateKeyTypes)
    assert unexisting_key is None


def test_generate_cert(monkeypatch, main_node):
    cert, key = generate_certificate(main_node.info)
    assert cert is not None
    assert key is not None
    device_id = main_node.info
    verified = verify_cert(cert, main_node.ca_cert, device_id)

    assert verified
    device_id.model = "changedModel"
    verified = verify_cert(cert, main_node.ca_cert, device_id)

    assert not verified


def test_save_cert(monkeypatch, main_node, folder_test, app):
    mock_logger = MagicMock()
    monkeypatch.setattr('flask.flash', lambda *args, **kwargs: None)
    monkeypatch.setattr(app.logger, 'error', mock_logger)
    cert = main_node.my_certificate
    key = main_node.my_private_key
    save_certificate(cert, folder_test, "saved_cert.pem")
    save_private_key(key, folder_test, "saved_private_key.key")

    saved_cert: CustomCertificate = load_certificate("saved_cert.pem", folder_test)
    saved_key = load_private_key("saved_private_key.key", folder_test)

    assert saved_cert is not None
    assert saved_cert.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())
    assert saved_key is not None
    assert saved_key.private_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                   encryption_algorithm=serialization.NoEncryption()) == key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

    mock_logger.assert_not_called()
    save_certificate(cert, 'asd/asd/asdd', "saved_cert.pem")
    save_private_key(key, 'asd/asd/asdd', "saved_private_key.key")

    mock_logger.assert_called()
