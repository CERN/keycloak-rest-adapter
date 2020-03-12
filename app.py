import os
from typing import Tuple

from authlib_helpers.decorators import AuthLibHelper
from flask import (
    Flask,
    redirect,
    send_from_directory,
)
from flask_cors import CORS
from flask_restplus import Api, apidoc

from auth import UserAuthLibHelper
from keycloak_api_client.keycloak import KeycloakAPIClient
from log_utils import configure_logging

# Required to have access to keycloak. ca-bundle is on centos
if os.environ.get("REQUESTS_CA_BUNDLE") is None:
    certs_base = "/etc/ssl/certs/"
    ca_certs = os.path.join(certs_base, "ca-certificates.crt")
    if not os.path.exists(ca_certs):
        ca_certs = os.path.join(certs_base, "ca-bundle.crt")
    os.environ["REQUESTS_CA_BUNDLE"] = ca_certs


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
    CORS(app)
    app.url_map.strict_slashes = False
    app.config.from_object("default_adapter_config")
    app.logger = configure_logging()
    read_env_config(app)

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


class ApiDoc:
    def __init__(self, title, specs_url):
        self.title = title
        self.specs_url = specs_url


@api.documentation
def custom_ui():
    specs_url = api.specs_url
    if application.config.get("OAUTH_HTTPS_SWAGGER", False) is True:
        specs_url = specs_url.replace("http://", "https://")
    return apidoc.ui_for(ApiDoc(api.title, specs_url))
