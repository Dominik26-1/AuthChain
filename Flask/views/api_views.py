from http import HTTPStatus

from flask import Blueprint
from flask import redirect, url_for, request, flash, Response, current_app

from app import app_node
from decorators.login import login_required
from enumeration import ErrorCategory
from model.core import ConfirmationData, Payload
from model.db.auth_block import AuthBlock
from model.db.auth_transaction import AuthTransaction
from model.db.cert_block import CertificateBlock
from model.db.cert_transaction import CertificateTransaction
from model.db.pay_block import PaymentBlock
from model.db.pay_transaction import PaymentTransaction
from model.json import JSONPayload, JSONConfirmationData, NodeData

api_blueprint = Blueprint('api_blueprint', __name__)


@api_blueprint.route('/', methods=['POST'])
def node_status():
    return Response('OK', status=HTTPStatus.OK)


@api_blueprint.route('/block', methods=['POST'])
def receive_block():
    json_data = request.get_json(True)
    block_type = json_data.get("type")
    current_app.logger.error(
        f"Bad request. {str(json_data)}, {block_type}")

    try:
        block_data: dict = json_data.get("block")
        if block_type is not None and block_type == AuthBlock.__name__:
            block = AuthBlock.from_dict(block_data, calculated_attrs=['block_hash'])
        elif block_type is not None and block_type == PaymentBlock.__name__:
            block = PaymentBlock.from_dict(block_data, calculated_attrs=['block_hash'])
        elif block_type is not None and block_type == CertificateBlock.__name__:
            block = CertificateBlock.from_dict(block_data, calculated_attrs=['block_hash'])
        else:
            flash(f"Bad request. Block data parsing failure.", ErrorCategory.ERROR.value)
            current_app.logger.error(
                f"Bad request. Block data parsing failure, unsupported block type: {block_type}.")
    except Exception as e:
        flash(f"Bad request. Block data parsing failure.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f"Bad request. Block data parsing failure with error {e}.")
        return None

    app_node.receive_block(block)
    return Response('OK', status=HTTPStatus.OK)


@api_blueprint.route('/transaction', methods=['POST'])
def receive_transaction():
    json_data: dict = request.get_json(True)
    trx_type = json_data.get("type")
    try:
        trx_data: dict = json_data.get("transaction")
        if trx_type is not None and trx_type == AuthTransaction.__name__:
            transaction = AuthTransaction.from_dict(trx_data)
        elif trx_type is not None and trx_type == PaymentTransaction.__name__:
            transaction = PaymentTransaction.from_dict(trx_data)
        elif trx_type is not None and trx_type == CertificateTransaction.__name__:
            transaction = CertificateTransaction.from_dict(trx_data)
        else:
            return
    except Exception as e:
        flash(f"Bad request. Transaction data parsing failure.", ErrorCategory.ERROR.value)
        current_app.logger.error(
            f"Bad request. Transaction data parsing failure with error {e}.")
        return None

    app_node.store_transaction(transaction)
    return Response('OK', status=HTTPStatus.OK)


@api_blueprint.route('/network_data', methods=['POST'])
def node_data():
    confirmation_data = __parse_accept_request(request)
    response_data = app_node.get_network_data(confirmation_data)
    if response_data:
        return response_data.to_dict()
    else:
        return 'Unauthorized access to retrieve network data.', HTTPStatus.UNAUTHORIZED


@api_blueprint.route('/blockchain_data', methods=['GET'])
@login_required
def blockchain_data():
    response_data = app_node.get_blockchain_data()
    return response_data.to_dict()


@api_blueprint.route('/sync', methods=['POST'])
def receive_sync_data():
    json_data = request.get_json(True)
    try:
        node_data = NodeData.from_dict(json_data)
    except Exception as e:
        current_app.logger.error(f'Error with parsing NodeData for heartbeat sync. {e}')
        flash(f"Bad response with nodes data for heartbeat sync", ErrorCategory.WARNING.value)
        return Response('Node data is not in correct form', status=HTTPStatus.BAD_REQUEST)

    app_node.update_nodes(node_data)
    return Response('OK', status=HTTPStatus.OK)


@api_blueprint.route('/handshake', methods=['POST'])
def receive_handshake():
    payload_data = __parse_request_handshake(request)
    if payload_data:
        app_node.receive_handshake(payload_data)
    return redirect(url_for('ui_blueprint.index'))


@api_blueprint.route('/connect', methods=['POST'])
def first_receive_handshake():
    received_request = request
    payload_data = __parse_request_handshake(received_request)

    if payload_data:
        app_node.receive_handshake(payload_data)
        app_node.broadcast_request(received_request.get_json(True), '/handshake')
        return Response('OK', status=HTTPStatus.OK)
    else:
        return Response(status=HTTPStatus.BAD_REQUEST)


@api_blueprint.route('/logout', methods=['POST'])
def logout_node():
    if not app_node.is_logged:
        flash("Already log out.", ErrorCategory.INFO.value)
        return redirect(url_for('ui_blueprint.index'))
    received_request = request
    json_payload_data = __parse_request_handshake(received_request)
    payload_data = Payload.build(json_payload_data)
    if payload_data:
        app_node.logout_another_node(payload_data.node_url, payload_data.node_id)
    return redirect(url_for('ui_blueprint.index'))


def __parse_request_handshake(received_request) -> JSONPayload | None:
    if received_request.method == "POST":
        json_data = received_request.get_json(True)

        try:
            request_data = JSONPayload.from_dict(json_data, False)
        except Exception as e:
            flash(f"Bad request. Handshake data parsing failure.", ErrorCategory.ERROR.value)
            current_app.logger.error(
                f"Bad request. Handshake data parsing failure with error {e}.")
            return None

        return request_data


@api_blueprint.route('/confirmation', methods=['POST'])
def receive_confirmation():
    if request.method == "POST":
        data = request.get_json(True)
        approved: bool = data.get("approved")
        verifier_url = data.get("node_url")
        if approved is None or verifier_url is None:
            return 'Zla confirmation odpoved', HTTPStatus.BAD_REQUEST
        app_node.handle_confirmation(approved, verifier_url)
    return redirect(url_for('ui_blueprint.index'))


@api_blueprint.route('/accept_create', methods=['POST'])
def accept_create():
    confirmation_data = __parse_accept_request(request)
    if confirmation_data:
        registered = app_node.register_another_node(confirmation_data)
        if registered:
            return Response('OK', status=HTTPStatus.OK)
        else:
            return Response('Unauthorized operation.', status=HTTPStatus.UNAUTHORIZED)
    return Response('Bad request', status=HTTPStatus.BAD_REQUEST)


@api_blueprint.route('/accept_registration', methods=['POST'])
def accept_registration():
    confirmation_data = __parse_accept_request(request)
    if confirmation_data:
        registered = app_node.register_another_node(confirmation_data)
        if registered:
            return Response('OK', status=HTTPStatus.OK)
        else:
            return Response('Unauthorized operation.', status=HTTPStatus.UNAUTHORIZED)
    return Response('Bad request', status=HTTPStatus.BAD_REQUEST)


@api_blueprint.route('/accept_login', methods=['POST'])
def accept_login():
    confirmation_data = __parse_accept_request(request)
    if confirmation_data:
        logged = app_node.login_another_node(confirmation_data)
        if logged:
            return Response('OK', status=HTTPStatus.OK)
        else:
            return Response('Unauthorized operation.', status=HTTPStatus.UNAUTHORIZED)
    return Response('Bad request', status=HTTPStatus.BAD_REQUEST)


def __parse_accept_request(received_request) -> ConfirmationData | None:
    if received_request.method == "POST":
        json_data = received_request.get_json(True)
        try:
            request_data = JSONConfirmationData.from_dict(json_data, False)
        except Exception as e:
            flash(f"Bad request. Confirmation data parsing failure.", ErrorCategory.ERROR.value)
            current_app.logger.error(
                f"Bad request. Confirmation data parsing failure with error {e}.")
            return None

        data = ConfirmationData.build(request_data)
        return data
