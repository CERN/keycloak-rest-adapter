from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import redirect
from api_definitions import api
from auth import auth_lib_helper
from keycloak_api_client.keycloak import keycloak_client
from log_utils import configure_logging
from flask import Blueprint

index_bp = Blueprint("index", __name__)


@index_bp.route("/")
def index():
    return redirect("/swagger-ui")


def _set_config_if_undefined(app, variable, value):
    if not app.config.get(variable):
        app.config.update(**{variable: value})


def configure_keycloak_dependent_variables(app: Flask) -> None:
    keycloak_server = app.config["KEYCLOAK_SERVER"]
    api_version = app.config["API_VERSION"]
    realm = app.config["OIDC_REALM"]
    authorizations = app.config["OAUTH_AUTHORIZATIONS"]
    authorizations["oauth2"].update(
        {
            "tokenUrl": f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/token",
            "authorizationUrl": f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/auth",
        }
    )
    # Configuration URL for all the keys of the Keycloak server
    _set_config_if_undefined(
        app,
        "OIDC_JWKS_URL",
        f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/certs",
    )
    # The 'iss' field in the token should match this
    _set_config_if_undefined(
        app, "OIDC_ISSUER", f"{keycloak_server}/auth/realms/{realm}"
    )
    # UI OAuth URL
    _set_config_if_undefined(
        app,
        "OAUTH_AUTH_URL",
        f"{keycloak_server}/auth/realms/{realm}/protocol/openid-connect/auth",
    )
    app.config.update(
        OAUTH_AUTHORIZATIONS=authorizations,
        API_URL_PREFIX="/api/{}".format(api_version),
    )


def read_env_config(app: Flask):
    try:
        app.config.from_envvar("KEYCLOAK_REST_ADAPTER_CONFIG")
    except Exception as e:
        app.logger.error(e)


def configure_keycloak_client(app: Flask):
    """
    Configures the keycloak client using the app's config
    """
    keycloak_client.init_app(app)


def configure_authlib_helper(app: Flask):
    """
    Configures the authorization helper
    """
    auth_lib_helper.init_app(app)


def setup_api(app: Flask):
    """
    Sets up the flast-restx API
    """
    api.authorizations = app.config["OAUTH_AUTHORIZATIONS"]
    api.version = app.config["API_VERSION"]
    api.prefix = app.config["API_URL_PREFIX"]
    api.init_app(app)


def create_app() -> Flask:
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    CORS(app)
    app.url_map.strict_slashes = False
    app.config.from_object("default_adapter_config")
    read_env_config(app)
    app.logger = configure_logging(app.config["LOG_DIR"])

    # Configuration
    configure_keycloak_dependent_variables(app)
    configure_keycloak_client(app)
    configure_authlib_helper(app)

    if app.config.get("OAUTH_AUTH_URL", None):
        app.config["OAUTH_AUTHORIZATIONS"]["oauth2"]["authorizationUrl"] = app.config[
            "OAUTH_AUTH_URL"
        ]

    setup_api(app)

    # Blueprints
    app.register_blueprint(index_bp)

    return app
