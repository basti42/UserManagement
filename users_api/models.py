import json
from enum import Enum

import jwt
import datetime

from users_api import db
from users_api.config import BaseConfig
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = generate_password_hash(
            password=password,
            salt_length=BaseConfig.SALT_LENGTH
        )
        self.registered_on = datetime.datetime.now()
        self.is_admin = admin

    def compare_password(self, _pw):
        return check_password_hash(
            pwhash=self.password,
            password=_pw
        )

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10.0),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                BaseConfig.SECRET_KEY,
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, BaseConfig.SECRET_KEY, algorithms=['HS256'])
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub'], payload["exp"]
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.', None
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.', None


class BlacklistToken(db.Model):
    """
    Token Model for storing revoked or blacklisted JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}>'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


class AuthTokens(db.Model):
    """
    Active JWT Tokens in use for resource access
    """
    __tablename__ = "auth_tokens"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    origin_header = db.Column(db.String, nullable=False)

    def __init__(self, _token: str, _origin_header: dict):
        self.token = _token
        self.created_on = datetime.datetime.now()
        self.origin_header = json.dumps(_origin_header)

    def __repr__(self):
        return '<id: jwt-token: {}>'.format(self.token)


class LogEvents(Enum):
    FailedLoginAttempt = 1
    SuccessfulLogin = 2
    InvalidToken = 3
    SuccessfulLogout = 4


class UserEventLog(db.Model):
    """
    Event log for user management
    """
    __tablename__ = "event_log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_name = db.Column(db.String(255), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    origin_user_agent = db.Column(db.String, nullable=False)
    origin_host = db.Column(db.String, nullable=False)

    def __init__(self, _event_name: LogEvents, _origin_header: dict):
        self.event_name = str(_event_name)
        self.event_datetime = datetime.datetime.now()
        self.origin_user_agent = _origin_header.get("User-Agent", "UNKNOWN")
        self.origin_host = _origin_header.get("Host", "UNKNOWN")
