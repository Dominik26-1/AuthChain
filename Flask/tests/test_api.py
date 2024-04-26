from datetime import datetime
from unittest.mock import MagicMock

import pytest
import requests
from flask_wtf.csrf import generate_csrf

from certificate.cert_convertor import convert_cert_to_str
from model.json import JSONPayload


@pytest.mark.usefixtures("client")
def test_node_availability(client):
    csrf_token = generate_csrf()
    # Nastavenie hlavičky pre CSRF token, ak je to potrebné
    headers = {
        "X-CSRFToken": csrf_token
    }
    data = {
        "csrf_token": csrf_token,  # Pridajte CSRF token ako súčasť dát
    }
    response = client.post('/api/', json=data, headers=headers)
    assert response.status_code == 200
    assert response.text == "OK"


@pytest.mark.usefixtures("client", "sender_node", "main_node", "app")
def test_connect_endpoint(client, sender_node, main_node, monkeypatch, app):
    mock_broadcast = MagicMock()
    mock_post_confirmation = MagicMock()
    from app import app_node
    monkeypatch.setattr(requests, 'post', mock_post_confirmation)
    monkeypatch.setattr(app_node, 'broadcast_request', mock_broadcast)
    monkeypatch.setattr(app.logger, 'info', lambda *args, **kwargs: None)

    sender_certificate_str = convert_cert_to_str(sender_node.my_certificate)
    json_data = JSONPayload(timestamp=datetime.now().isoformat(), node_url=sender_node.url,
                            node_id=sender_node.info.to_dict(),
                            action_name="SIGNUP", cert_string=sender_certificate_str)
    json_data.sign_payload(sender_node.my_private_key)
    json_dict = json_data.to_dict()

    response = client.post('/api/connect', json=json_dict)
    mock_post_confirmation.assert_called()
    confirmation_dict = mock_post_confirmation.call_args[1]['json']
    assert confirmation_dict['approved']
    assert confirmation_dict['node_url'] == main_node.url
    assert response.status_code == 200
    assert response.text == "OK"
