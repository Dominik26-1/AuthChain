import logging
import os
from logging.handlers import RotatingFileHandler

from flask import current_app

# Create a file handler
file_handler = RotatingFileHandler(os.path.join(current_app.root_path, *['logs', 'app.log']), maxBytes=10240,
                                   backupCount=10)

# Set the log level
file_handler.setLevel(logging.INFO)

# Create a logging format
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(formatter)
