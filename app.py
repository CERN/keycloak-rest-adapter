from typing import Tuple

from authlib_helpers.decorators import AuthLibHelper
from flask import (
    Flask,
    redirect,
    send_from_directory,
)
from werkzeug.contrib.fixers import ProxyFix
from flask_cors import CORS
from flask_restx import Api

from auth import UserAuthLibHelper
from keycloak_api_client.keycloak import KeycloakAPIClient
from log_utils import configure_logging


def configure_keycloak_dependent_variables(app: Flask) -> None:
    keycloak_server = app.config["KEYCLOAK_SERVER"]
    api_version = app.config['API_VERSION']
    realm = app.config["KEYCLOAK_REALM"]
    app.config.update(
        # The URL of the endpoint that initiates authentication
        SWAGGER_AUTHORIZATION_URL=f"https://{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/auth",
        # Configuration URL for all the keys of the Keycloak server
        OIDC_JWKS_URL=f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/certs",
        # The 'iss' field in the token should match this
        OIDC_ISSUER=f"{keycloak_server}/auth/realms/{realm}",
        OAUTH_AUTH_URL=f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/auth",
        API_URL_PREFIX="/api/{}".format(api_version)
    )


def read_env_config(app: Flask):
    try:
        app.config.from_envvar("KEYCLOAK_REST_ADAPTER_CONFIG")
    except Exception as e:
        app.logger.error(e)
    pass


def configure_keycloak_client(app: Flask) -> KeycloakAPIClient:
    return KeycloakAPIClient(app.config['KEYCLOAK_SERVER'], app.config['KEYCLOAK_REALM'],
                             app.config['KEYCLOAK_CLIENT_ID'],
                             app.config['KEYCLOAK_CLIENT_SECRET'])


def configure_authlib_helper(app: Flask) -> AuthLibHelper:
    return UserAuthLibHelper(
        access_role=app.config['AUTH_API_ACCESS_ROLE'],
        user_access_role=app.config['AUTH_USER_ACTIONS_ROLE'],
        multifactor_role=app.config['AUTH_USER_ACTIONS_MFA_ROLE'],
        client_id=app.config['OIDC_CLIENT_ID'],
        authorized_apps=app.config['AUTH_AUTHORIZED_APPS'],
        oidc_jwks_url=app.config['OIDC_JWKS_URL'],
        oidc_issuer=app.config['OIDC_ISSUER'],
        logger=app.logger
    )


def create_api(app: Flask) -> Api:
    api_builder = Api(
        app,
        version=app.config['API_VERSION'],
        title="Keycloak Rest Adapter API",
        description="A simple Keycloak adapter for handling clients",
        prefix=app.config['API_URL_PREFIX'],
        authorizations=app.config['OAUTH_AUTHORIZATIONS'],
        security=[{"oauth2": "api"}],
        doc="/swagger-ui",
    )
    return api_builder


def create_app() -> Tuple[Flask, Api]:
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    CORS(app)
    app.url_map.strict_slashes = False
    app.config.from_object("default_adapter_config")
    app.logger = configure_logging()
    read_env_config(app)
    configure_keycloak_dependent_variables(app)
    app.config['KEYCLOAK_CLIENT'] = configure_keycloak_client(app)
    app.config['AUTH_LIB_HELPER'] = configure_authlib_helper(app)

    if app.config.get('OAUTH_AUTH_URL', None):
        app.config['OAUTH_AUTHORIZATIONS']['oauth2'][
            'authorizationUrl'] = app.config['OAUTH_AUTH_URL']

    api_builder = create_api(app)

    return app, api_builder


application, api = create_app()


@application.route("/")
def index():
    return redirect("/swagger-ui")


@application.route("/oauth2-redirect.html")
def redirect_oauth():
    return send_from_directory("static", "oauth2-redirect.html")
