import datetime

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from users_api.db import db
from users_api.models import User, BlacklistToken, AuthTokens
from users_api.models import LogEvents, UserEventLog

auth_blueprint = Blueprint('auth', __name__, url_prefix="/api/v1/")


class StatusAPI(MethodView):
    def get(self):
        return make_response(jsonify({
            "status": "ok",
            "message": "api up and running"
        }))


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    username=post_data.get('username'),
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                response_object = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token
                }
                return make_response(jsonify(response_object)), 201
            except Exception as e:
                response_object = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(response_object)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        try:
            email = request.get_json()['email']
            pw = request.get_json()['password']
            try:
                user = User.query.filter_by(email=email).first()
                if user:
                    if user.compare_password(_pw=pw):
                        auth_token = user.encode_auth_token(user.id)
                        if auth_token:
                            response_object = {
                                "status": "success",
                                "message": "successfully logged in",
                                "auth_token": auth_token
                            }
                            event = UserEventLog(_event_name=LogEvents.SuccessfulLogin,
                                                 _origin_header=dict(request.headers))
                            db.session.add(event)
                            db.session.commit()
                            return make_response(jsonify(response_object)), 200
                    # password does not match
                    else:
                        response_object = {
                            "status": "fail",
                            "message": "incorrect password"
                        }
                        event = UserEventLog(_event_name=LogEvents.FailedLoginAttempt, _origin_header=dict(request.headers))
                        db.session.add(event)
                        db.session.commit()
                        return make_response(jsonify(response_object)), 401
                # user does not exist
                else:
                    response_object = {
                        "status": "fail",
                        "message": "User does not exist"
                    }
                    return make_response(jsonify(response_object)), 401
            except Exception as ex:
                response_object = {
                    "status": "error",
                    "message": f"something went wrong with reason: {ex}"
                }
                return make_response(jsonify(response_object)), 401
        # if email or pw were not provided as payload
        except KeyError as key_error:
            response_object = {
                "status": "fail",
                "message": "missing payload information"
            }
            return make_response(jsonify(response_object)), 401


class UserAPI(MethodView):
    """
    User information resource
    """
    def get(self):
        auth_header = request.headers.get("Authorization", None)
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError as idx_error:
                response_object = {
                    "status": "fail",
                    "message": "Bearer Token malformed"
                }
                return make_response(jsonify(response_object)), 401
        else:
            auth_token = ""
        if auth_token:
            result, expiration_date = User.decode_auth_token(auth_token=auth_token)
            if not isinstance(result, str):  # result is an int, if its a string, then its an error string
                user = User.query.filter_by(id=result).first()
                response_object = {
                    "status": "success",
                    "data": {
                        "username": user.username,
                        "email": user.email,
                        "registered_on": user.registered_on,
                        "token_exp_date": datetime.datetime.utcfromtimestamp(expiration_date).strftime('%Y-%m-%d %H:%M:%S')
                    }
                }
                return make_response(jsonify(response_object)), 200
            # auth token is of the wrong type
            response_object = {
                "status": "fail",
                "message": f"token is: {result}"
            }
            event = UserEventLog(_event_name=LogEvents.InvalidToken, _origin_header=dict(request.headers))
            db.session.add(event)
            db.session.commit()
            return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                    "status": "fail",
                    "message": "provide a valid bearer token"
                }
            return make_response(jsonify(response_object)), 401


class LogoutAPI(MethodView):
    """
    User logout resource
    """
    def post(self):
        auth_header = request.headers.get("Authorization", None)
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError as idx_error:
                response_object = {
                    "status": "fail",
                    "message": "Bearer Token malformed"
                }
                return make_response(jsonify(response_object)), 401
        else:
            auth_token = ""
        if auth_token:
            result, expiration_date = User.decode_auth_token(auth_token=auth_token)
            if not isinstance(result, str):  # result is an int, if its a string, then its an error string
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    response_object = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    # make log event
                    event = UserEventLog(_event_name=LogEvents.SuccessfulLogout, _origin_header=dict(request.headers))
                    db.session.add(event)
                    db.session.commit()
                    return make_response(jsonify(response_object)), 200
                except Exception as e:
                    response_object = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(response_object)), 200
            # auth token is of the wrong type
            response_object = {
                "status": "fail",
                "message": f"token is: {result}"
            }
            event = UserEventLog(_event_name=LogEvents.InvalidToken, _origin_header=dict(request.headers))
            db.session.add(event)
            db.session.commit()
            return make_response(jsonify(response_object)), 401
        # if logout does not work, then its probably an invalid token
        event = UserEventLog(_event_name=LogEvents.InvalidToken, _origin_header=dict(request.headers))
        db.session.add(event)
        db.session.commit()
        response_object = {
            "status": "fail",
            "message": "Invalid Token"
        }
        db.session.add(event)
        db.session.commit()
        return make_response(jsonify(response_object))


status_view = StatusAPI.as_view("status_api")
registration_view = RegisterAPI.as_view("register_api")
login_view = LoginAPI.as_view("login_api")
user_api = UserAPI.as_view("user_api")
logout_api = LogoutAPI.as_view("logout_api")


auth_blueprint.add_url_rule(
    rule="/",
    view_func=status_view,
    methods=["GET"]
)

auth_blueprint.add_url_rule(
    rule="/auth/register",
    view_func=registration_view,
    methods=["POST"]
)

auth_blueprint.add_url_rule(
    rule="/auth/login",
    view_func=login_view,
    methods=["POST"]
)

auth_blueprint.add_url_rule(
    rule="/auth/user",
    view_func=user_api,
    methods=["GET"]
)

auth_blueprint.add_url_rule(
    rule="/auth/logout",
    view_func=logout_api,
    methods=["POST"]
)
