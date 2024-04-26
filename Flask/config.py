import os
from datetime import timedelta


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if SECRET_KEY is None:
        raise AttributeError('No SECRET_KEY set')
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('POSTGRES_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #DEBUG = True
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CERT_FOLDER_PATH = os.path.join(BASE_DIR, *['static', 'certs', ''])
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # More configuration variables can be added here
