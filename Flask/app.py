import logging
import os

# from beaker.middleware import SessionMiddleware
from flask import Flask, session
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base

from config import Config
from node.node_instance import create_node_instance
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS

from utils.secret_utils import get_secret_value

app = Flask(__name__, template_folder='templates')

app.config.from_object(Config)
# csrf = CSRFProtect(app)
# CORS(app, supports_credentials=True)
ip_address = os.getenv('DOMAIN_NAME', '127.0.0.1')
name = os.getenv('DEVICE_NAME', 'PC_ID')
port = int(os.getenv('PORT', '5000'))

#mac_address = os.getenv('MAC_ADDRESS', "dummy")
#model = os.getenv('MODEL', 'dummy')
#serial_number = os.getenv('SERIAL_NUMBER', 'dummy')

mac_address = get_secret_value('secret1', 'dummy')
serial_number = get_secret_value('secret2', 'dummy')
model = get_secret_value('secret3', 'dummy')

Base = declarative_base()
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)

# Must be imports of models
# Required imports all parent models from where is Base object declared
# Without that creation of table would be not proceed
from model.db import *  # noqa: F401
from model.common.common import *  # noqa: F401

with app.app_context():
    app.config['SESSION_COOKIE_DOMAIN'] = None
    app.config['SESSION_COOKIE_SAMESITE'] = None
    app.config['SESSION_COOKIE_SECURE'] = False

    Base.metadata.create_all(bind=engine)
    app_node = create_node_instance(name, ip_address, port, mac_address, model, serial_number)

    from views import api_blueprint, ui_blueprint
    from logger import file_handler

    # Nastavenie úrovne logovania
    app.logger.setLevel('DEBUG')
    # Add the file handler to the Flask app's logger
    app.logger.addHandler(file_handler)
    # Set the log level for the logger
    app.logger.setLevel(logging.DEBUG)

    app.register_blueprint(api_blueprint, url_prefix='/api')
    app.register_blueprint(ui_blueprint)
    # app.wsgi_app = SessionMiddleware(app.wsgi_app, session_opts)
