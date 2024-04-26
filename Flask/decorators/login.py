import socket
from functools import wraps

from flask import request, abort

from app import app_node


def local_endpoint(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.headers.get('X-Real-IP')
        server_ip = request.host.split(':')[0]
        ips = [server_ip, '172.21.0.1']
        try:
            ips.extend(socket.gethostbyname_ex(server_ip)[2])
        except:
            pass

        if client_ip not in ips:
            return abort(403)

        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app_node.is_logged():
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function
