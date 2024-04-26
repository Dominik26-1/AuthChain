from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from flask import request, render_template, Blueprint, redirect, url_for, flash, abort, current_app

from app import app_node
from certificate.cert_convertor import convert_str_to_cert, convert_bytes_to_key, convert_bytes_to_cert, \
    convert_cert_to_str
from certificate.cert_generator import generate_certificate
from certificate.cert_saver import save_certificate, save_private_key
from config import Config
from constants import ENTRY_URL, ENTRY_PORT, MAX_PAGE_ITEM
from decorators.login import local_endpoint, login_required
from enumeration import ErrorCategory
from enumeration.action import Action
from model.core.certificate import CustomCertificate
from model.db.auth_transaction import AuthTransaction
from model.db.cert_transaction import CertificateTransaction
from model.db.pay_transaction import PaymentTransaction

ui_blueprint = Blueprint('ui_blueprint', __name__)


@ui_blueprint.route('/')
@local_endpoint
def index():
    if app_node.is_logged():
        return render_template('network.html', node=app_node)
    else:
        return render_template('index.html', node=app_node)


@ui_blueprint.route('/generate_certificate', methods=['GET', 'POST'])
def apply_certificate():
    cert, key = generate_certificate(app_node.info)
    save_certificate(cert, Config.CERT_FOLDER_PATH, 'new_cert.pem')
    save_private_key(key, Config.CERT_FOLDER_PATH, 'new_private_key.pem')
    return redirect(url_for('ui_blueprint.index'))


@ui_blueprint.route('/create_network', methods=['GET', 'POST'])
@local_endpoint
def create_network():
    if request.method == "GET":
        if f'https://{ENTRY_URL}:{ENTRY_PORT}/api' != app_node.url:
            flash("Do not have permission to create network", ErrorCategory.ERROR.value)
            current_app.logger.info(f"Creation of network failed on permission for node: {app_node.url}")
            return redirect(url_for('ui_blueprint.index'))
        return render_template("entry_form.html", context={"target": "/create_network"})
    else:
        if f'https://{ENTRY_URL}:{ENTRY_PORT}/api' != app_node.url:
            flash("Do not have permission to create network", ErrorCategory.ERROR.value)
            current_app.logger.info(f"Creation of network failed on permission for node: {app_node.url}")
            return redirect(url_for('ui_blueprint.index'))
        cert, private_key = __parse_uploaded_certificate(request)
        if cert is None or private_key is None:
            return redirect(url_for('ui_blueprint.index'))

        app_node.set_credentials(cert, private_key)
        network_creator: bool = app_node.send_handshake(app_node.url, Action.CREATE)
        if network_creator:
            app_node.open_session()
            flash("Successfully started network", ErrorCategory.INFO.value)
            current_app.logger.info(f"Successfully created network by {app_node.url}")
            app_node.generate_trx(trx_class=AuthTransaction, action_type=Action.CREATE.name)
            app_node.generate_trx(trx_class=CertificateTransaction, certificate=convert_cert_to_str(cert))
        else:
            flash("Cannot started network due to verification of certificate", ErrorCategory.ERROR.value)
            current_app.logger.info(f"Cannot started network due to verification of certificate by {app_node.url}")
        app_node.confirmations.clear()
        return redirect(url_for('ui_blueprint.index'))


@ui_blueprint.route('/register', methods=['GET', 'POST'])
@local_endpoint
def signup_page():
    if request.method == "GET":
        return render_template("entry_form.html", context={"target": "/register"})
    else:
        cert, private_key = __parse_uploaded_certificate(request)
        if cert is None or private_key is None:
            return redirect(url_for('ui_blueprint.index'))
        app_node.set_credentials(cert, private_key)
        # Otvorenie súboru a odoslanie ako časti multipart/form-data

        neighbour_url = f'https://{ENTRY_URL}:{ENTRY_PORT}/api'

        is_registered = app_node.send_handshake(neighbour_url, Action.SIGNUP)
        if is_registered:
            app_node.open_session()
            flash("Successfully signed up", ErrorCategory.INFO.value)
            app_node.generate_trx(trx_class=AuthTransaction, action_type=Action.SIGNUP.name)
            app_node.generate_trx(trx_class=CertificateTransaction, certificate=convert_cert_to_str(cert))
        else:
            flash("Registration rejected", ErrorCategory.INFO.value)
        app_node.confirmations.clear()
        return redirect(url_for('ui_blueprint.index'))


def __parse_uploaded_certificate(received_request) -> (CustomCertificate | None, PrivateKeyTypes | None):
    if received_request.method == "POST":
        if 'cert_file' not in request.files or 'key_file' not in request.files:
            flash("Not loaded certificate or key file.", ErrorCategory.ERROR.value)
            current_app.logger.error(
                "Not loaded certificate or key file.")
            return None, None
        pem_file = request.files.get('cert_file')
        key_file = request.files.get('key_file')

        # Ak užívateľ nevybral súbor, prehliadač tiež
        # odosiela prázdny súbor bez názvu.
        if pem_file.filename == '' or key_file.filename == '':
            flash("Empty certificate or key file.", ErrorCategory.ERROR.value)
            current_app.logger.error(
                "Empty certificate or key file.")
            return None, None

        if (pem_file and pem_file.filename.endswith('.pem')) and (key_file and key_file.filename.endswith('.pem')):
            try:
                pem_data = pem_file.read()
                cert = convert_bytes_to_cert(pem_data)
                key_data = key_file.read()
                private_key = convert_bytes_to_key(key_data)
            except Exception as e:
                flash("Bad request. Certificate data parsing failure.", ErrorCategory.ERROR.value)
                current_app.logger.error(
                    f"Bad request. Certificate data parsing failure with error {e}.")
                return None, None
            return cert, private_key
        else:
            flash('Invalid certificate or key file type.', ErrorCategory.ERROR.value)
            current_app.logger.error(
                "Invalid certificate or key file type.")
            return None, None


@ui_blueprint.route('/login', methods=['GET', 'POST'])
@local_endpoint
def login_page():
    if request.method == "GET":
        return render_template("entry_form.html", context={"target": "/login"})
    else:
        cert, private_key = __parse_uploaded_certificate(request)
        if cert is None or private_key is None:
            return redirect(url_for('ui_blueprint.index'))
        app_node.set_credentials(cert, private_key)

        neighbour_url = f'https://{ENTRY_URL}:{ENTRY_PORT}/api'

        logged = app_node.send_handshake(neighbour_url, Action.LOGIN)
        if logged:
            flash("Successfully logged in", ErrorCategory.INFO.value)
            app_node.generate_trx(trx_class=AuthTransaction, action_type=Action.LOGIN.name)
            app_node.open_session()
        else:
            flash("Login rejected", ErrorCategory.INFO.value)
        app_node.confirmations.clear()
        return redirect(url_for('ui_blueprint.index'))


@ui_blueprint.route('/logout')
@local_endpoint
def logout_page():
    app_node.close_session()
    app_node.logout_me()
    return redirect(url_for('ui_blueprint.index'))

@ui_blueprint.route('/payment/', methods=['GET', 'POST'])
@local_endpoint
@login_required
def create_payment():
    if request.method == "GET":
        return render_template("pay_transaction_form.html")
    elif request.method == "POST":
        price = float(request.form['price'])
        app_node.generate_trx(trx_class=PaymentTransaction, price=price)
        return redirect(url_for('ui_blueprint.index'))
@ui_blueprint.route('/auth-transaction/', methods=['GET'])
@local_endpoint
@login_required
def get_auth_transactions():
    page = request.args.get('page', 1, type=int)
    block_trx: list[AuthTransaction] = app_node.auth_blockchain.get_trx()
    trx_pool: list[AuthTransaction] = app_node.auth_transaction_pool.transactions

    all_trx: list[AuthTransaction] = sorted((block_trx + trx_pool), key=lambda trx: trx.creation_timestamp,
                                            reverse=True)
    start_trx_index = (page - 1) * MAX_PAGE_ITEM
    end_trx_index = page * MAX_PAGE_ITEM - 1

    if len(all_trx) == 0:
        page_trx = []
    else:
        page_trx = all_trx[start_trx_index:min(end_trx_index, len(all_trx))]

    return render_template("list_auth_transactions.html", **{"transactions": page_trx,
                                                             "all_trx_count": len(all_trx),
                                                             "trx_start_range": start_trx_index,
                                                             "trx_end_range": end_trx_index,
                                                             "actual_page": page,
                                                             "per_page": MAX_PAGE_ITEM
                                                             })

@ui_blueprint.route('/profile/<string:node_id>', methods=['GET'])
@local_endpoint
@login_required
def get_profile(node_id: str):
    node_record: tuple[str, str] | None = next(filter(lambda node_record: node_record[1] == node_id,
                                                      app_node.get_network_nodes()))
    node_cert_dict = {}
    if not node_record:
        node_url = "unknown"
    else:
        node_url = node_record[0]
    node_cert = app_node.node_certs.get(node_id)
    if node_cert:
        node_cert_dict = node_cert.to_dict()
    node_auth_trx: list[AuthTransaction] = app_node.auth_transaction_pool.get_node_trx(
        node_id) + app_node.auth_blockchain.get_node_trx(node_id)
    node_pay_trx: list[PaymentTransaction] = app_node.pay_transaction_pool.get_node_trx(
        node_id) + app_node.pay_blockchain.get_node_trx(node_id)
    node_name = "unknown"
    if len(node_auth_trx) != 0:
        node_name = node_auth_trx[0].node_name

    return render_template("node_profile.html", **{"node_url": node_url,
                                                   "node_cert": node_cert_dict,
                                                   "auth_trx": node_auth_trx,
                                                   "pay_trx": node_pay_trx,
                                                   "node_name": node_name})


@ui_blueprint.route('/pay-transaction/', methods=['GET'])
@local_endpoint
@login_required
def get_pay_transactions():
    page = request.args.get('page', 1, type=int)
    block_trx: list[PaymentTransaction] = app_node.pay_blockchain.get_trx()
    trx_pool: list[PaymentTransaction] = app_node.pay_transaction_pool.transactions

    all_trx: list[PaymentTransaction] = sorted((block_trx + trx_pool), key=lambda trx: trx.creation_timestamp,
                                               reverse=True)
    start_trx_index = (page - 1) * MAX_PAGE_ITEM
    end_trx_index = page * MAX_PAGE_ITEM - 1

    if len(all_trx) == 0:
        page_trx = []
    else:
        page_trx = all_trx[start_trx_index:min(end_trx_index, len(all_trx))]

    return render_template("list_pay_transactions.html", **{"transactions": page_trx,
                                                            "all_trx_count": len(all_trx),
                                                            "trx_start_range": start_trx_index,
                                                            "trx_end_range": end_trx_index,
                                                            "actual_page": page,
                                                            "per_page": MAX_PAGE_ITEM
                                                            })