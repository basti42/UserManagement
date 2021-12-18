import os
import secrets
basedir = os.path.abspath(os.path.dirname(__file__))
database_schema = 'sqlite:///'
database_name = 'user_management.sqlite'


class BaseConfig(object):
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(nbytes=32))
    DEBUG = os.getenv("DEBUG", False)
    SALT_LENGTH = os.getenv("SALT_LENGTH", 16)
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI", database_schema + database_name)
