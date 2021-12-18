import os
from flask import Flask
from flask_cors import CORS

from users_api.db import db
from users_api.auth.views import auth_blueprint


def create_app():
    _app = Flask(__name__)
    CORS(_app)

    #
    #  set application config
    #
    settings = os.getenv(
        "APP_SETTINGS",
        "users_api.config.BaseConfig"
    )
    _app.config.from_object(settings)

    #
    #  init database with app
    #
    db.init_app(_app)

    with _app.app_context():
        #
        #  register the blueprints for the routes
        #
        _app.register_blueprint(auth_blueprint)

        #
        #  create all databases from the models
        #
        db.create_all()
        return _app
