import json
import os

from configparser import ConfigParser
from flask import (
    Flask,
    make_response,
    request,
    redirect,
    url_for,
    send_from_directory,
    jsonify,
)
from flask_oidc import OpenIDConnect
from flask_restplus import Resource, Api, Namespace, fields, apidoc
from keycloak_api_client.keycloak import KeycloakAPIClient

from utils import (
    json_response,
    get_request_data,
    is_xml,
    validate_protocol,
    validate_protocol_data,
    config_dir,
    SUPPORTED_PROTOCOLS,
    auth_protocols,
)

# Required to have access to keycloak. ca-bundle is on centos
if os.environ.get("REQUESTS_CA_BUNDLE") is None:
    certs_base = "/etc/ssl/certs/"
    ca_certs = os.path.join(certs_base, "ca-certificates.crt")
    if not os.path.exists(ca_certs):
        ca_certs = os.path.join(certs_base, "ca-bundle.crt")
    os.environ["REQUESTS_CA_BUNDLE"] = ca_certs

privatekey_file = "{0}/keycloak-rest-adapter_nopass.key".format(config_dir)
certificate_file = "{0}/keycloak-rest-adapter.crt".format(config_dir)
keycloakclient_config_file = "{0}/keycloak_client.cfg".format(config_dir)
flask_oidc_client_secrets_file = "{0}/flask_oidc_config.json".format(config_dir)

API_VERSION = "v1.0"
API_URL_PREFIX = "/api/{}".format(API_VERSION)


##################################
# not very elengant, see ->
# https://stackoverflow.com/questions/25925217/object-oriented-python-with-flask-server/25925286

config = ConfigParser()
config.readfp(open(keycloakclient_config_file))

keycloak_server = config.get("keycloak", "server")
realm = config.get("keycloak", "realm")
admin_user = config.get("keycloak", "admin_user")
admin_password = config.get("keycloak", "admin_password")
client_id = config.get("keycloak", "keycloak_rest_adapter_client")
client_secret = config.get("keycloak", "keycloak_rest_adapter_client_secret")

keycloak_client = KeycloakAPIClient(
    keycloak_server, realm, admin_user, admin_password, client_id, client_secret
)

ui_authorization_url = config.get("oauth", "auth_url", fallback=None)
if not ui_authorization_url:
    ui_authorization_url = "{}/auth/realms/master/protocol/openid-connect/auth".format(
        keycloak_server
    )

authorizations = {
    "oauth2": {
        "type": "oauth2",
        "flow": "implicit",
        "authorizationUrl": ui_authorization_url,
    }
}

app = Flask(__name__)
api = Api(
    app,
    version=API_VERSION,
    title="Keycloak Rest Adapter API",
    description="A simple Keycloak adapter for handling clients",
    prefix=API_URL_PREFIX,
    authorizations=authorizations,
    security=[{"oauth2": "api"}],
    doc="/swagger-ui",
)


class ApiDoc:
    def __init__(self, title, specs_url):
        self.title = title
        self.specs_url = specs_url


@api.documentation
def custom_ui():
    specs_url = api.specs_url
    if config.get("oauth", "https_swagger", fallback=False):
        specs_url = specs_url.replace("http://", "https://")
    return apidoc.ui_for(ApiDoc(api.title, specs_url))


app.config.SWAGGER_UI_OAUTH_REDIRECT_URL = config.get("oauth", "redirect_url")
app.config.SWAGGER_UI_OAUTH_CLIENT_ID = config.get(
    "keycloak", "keycloak_rest_adapter_client"
)
app.config.SWAGGER_UI_OAUTH_APP_NAME = "Keycloak REST Adapter"
ns = api.namespace("client", description="Client operations")
user_ns = api.namespace("user", description="Methods for handling user operations")

# Models
model = ns.model("Payload", {"clientId": fields.String}, required=False)
token_exchange_payload = ns.model(
    "TokenExchange", {"target": fields.String, "requestor": fields.String}
)

app.config.update(
    {
        "SECRET_KEY": "WHATEVER",
        "TESTING": True,
        "DEBUG": True,
        "OIDC-SCOPES": ["openid"],
        "OIDC_CLIENT_SECRETS": flask_oidc_client_secrets_file,
        "OIDC_INTROSPECTION_AUTH_METHOD": "client_secret_post",
        "OIDC_OPENID_REALM": "master",
        "OIDC_TOKEN_TYPE_HINT": "access_token",
        "OIDC_RESOURCE_SERVER_ONLY": True,
    }
)

oidc = OpenIDConnect(app)

### Done with the config


@app.route("/")
def index():
    return redirect("/swagger-ui")


@app.route("/oauth2-redirect.html")
def redirect_oauth():
    return send_from_directory("static", "oauth2-redirect.html")


@ns.route("/token-exchange-permissions")
class TokenExchangePermissions(Resource):
    @ns.doc(body=token_exchange_payload)
    @oidc.accept_token(require_token=True)
    def post(self):
        """Grants new token exchange permissions"""
        data = get_request_data(request)
        validation_error = self.__validate(data)
        if validation_error:
            return validation_error
        
        target_client_name = data["target"]
        requestor_client_name = data["requestor"]

        target_client = keycloak_client.get_client_by_clientID(target_client_name)
        requestor_client = keycloak_client.get_client_by_clientID(requestor_client_name)

        verify_error = self.__verify_clients(target_client, requestor_client, target_client_name, requestor_client_name)
        if verify_error:
            return verify_error

        ret = keycloak_client.grant_token_exchange_permissions(
            target_client["id"], requestor_client["id"]
        )
        if ret.status_code == 200 or ret.status_code == 201:
            return ret.reason, 200
        else:
            return ret.reason, 400

    @ns.doc(body=token_exchange_payload)
    @oidc.accept_token(require_token=True)
    def delete(self):
        """Revokes token exchange permissions"""
        data = get_request_data(request)
        validation_error = self.__validate(data)
        if validation_error:
            return validation_error

        target_client_name = data["target"]
        requestor_client_name = data["requestor"]

        target_client = keycloak_client.get_client_by_clientID(target_client_name)
        requestor_client = keycloak_client.get_client_by_clientID(requestor_client_name)

        verify_error = self.__verify_clients(target_client, requestor_client, target_client_name, requestor_client_name)
        if verify_error:
            return verify_error
        try:
            ret = keycloak_client.revoke_token_exchange_permissions(
                target_client["id"], requestor_client["id"]
            )
        except ValueError as e:
            return e.args[0], 400
        if ret.status_code == 200 or ret.status_code == 201:
            return "Deleted", 200
        else:
            return ret.reason, 400

    def __validate(self, data):
        if not data or "target" not in data or "requestor" not in data:
            return json_response(
                "The request is missing 'target' or 'requestor'. They must be passed as a query parameter",
                400,
            )
        else:
            return False

    def __verify_clients(self, target_client, requestor_client, target_client_name, requestor_client_name):
        if target_client and requestor_client:
            return False
        else:
            return json_response(
                "Verify '{0}' and '{1}' exist".format(
                    target_client_name, requestor_client_name
                ),
                400,
            )


@ns.route("/<protocol>/<path:clientId>")
class ClientDetails(Resource):
    @ns.doc(body=model)
    @oidc.accept_token(require_token=True)
    def put(self, protocol, clientId):
        """Update a client"""
        data = get_request_data(request)
        if (protocol == "saml") and ("definition" in data):
            data = keycloak_client.client_description_converter(data["definition"])
        updated_client = keycloak_client.update_client_properties(clientId, **data)
        if updated_client:
            return jsonify(updated_client)
        else:
            return json_response(
                "Cannot update '{0}' properties. Check if client exists or properties are valid".format(
                    clientId
                ),
                400,
            )

    @oidc.accept_token(require_token=True)
    def delete(self, protocol, clientId):
        """Delete a client"""
        validation = validate_protocol(protocol)
        if validation:
            return validation
        ret = keycloak_client.delete_client_by_clientID(clientId)
        if ret != None:
            return json_response(
                "Client '{0}' deleted successfully".format(clientId), 200
            )
        else:
            return json_response(
                "Cannot delete client '{0}'. Client not found".format(clientId), 404
            )


@ns.route("/openid/<string:clientId>/regenerate-secret")
class OpenIdRegenerateSecret(Resource):
    @oidc.accept_token(require_token=True)
    def post(self, clientId):
        ret = keycloak_client.regenerate_client_secret(clientId)
        if ret:
            return jsonify(ret.json())
        else:
            return json_response(
                "Cannot reset '{0}' secret. Client not found".format(clientId), 404
            )


class CommonCreator(Resource):
    def common_create(self, data):
        """
        Common create method for all the endpoints
        """
        protocol = data["protocol"]
        selected_protocol_id = auth_protocols[protocol]
        if selected_protocol_id in data:
            if is_xml(data[selected_protocol_id]):
                # if data looks like XML use the client description converter to create client
                client_description = keycloak_client.client_description_converter(
                    data[selected_protocol_id]
                )
                # load saml protocol mappers
                with open("{0}/client_{1}_protocol_mappers.json".format(config_dir, protocol)) as f:
                    default_saml_protocol_mappers = json.load(f)
                client_description["protocolMappers"] = default_saml_protocol_mappers[
                    "protocolMappers"
                ]
                new_client = keycloak_client.create_new_client(**client_description)
            else:
                if protocol == "openid" and "protocolMappers" not in data:
                    # if not protocolMappers load default openid protocol mappers
                    with open("{0}/client_{1}_protocol_mappers.json".format(config_dir, protocol)) as f:
                        default_openid_protocol_mappers = json.load(f)
                    data["protocolMappers"] = default_openid_protocol_mappers[
                        "protocolMappers"
                    ]
                new_client = keycloak_client.create_new_client(**data)
        else:
            return json_response(
                "The request is missing '{}'. It must be passed as a query parameter".format(
                    selected_protocol_id
                ),
                400,
            )
        try:
            return jsonify(new_client)
        except Exception as ex:
            return json_response(
                "Unknown error creating client: {}".format(new_client), 400
            )


@ns.route("/<string:protocol>")
class CreatorDetails(CommonCreator):
    @ns.doc(body=model)
    @oidc.accept_token(require_token=True)
    def post(self, protocol):
        data = get_request_data(request)
        data["protocol"] = protocol
        validation = validate_protocol_data(data)
        if validation:
            return validation
        return self.common_create(data)


@ns.route("/")
class Creator(CommonCreator):
    @ns.doc(body=model)
    @oidc.accept_token(require_token=True)
    def post(self):
        data = get_request_data(request)
        validation = validate_protocol_data(data)
        if validation:
            return validation
        return self.common_create(data)


@user_ns.route("/logout/<string:user_id>")
class UserLogout(Resource):
    @oidc.accept_token(require_token=True)
    def delete(self, user_id):
        """
        Logout the user with the specified user_id from all sessions
        
        user_id: the user id (GUID)
        """
        if not user_id:
            return json_response("The request has an invalid 'user_id'", 400)
        response = keycloak_client.logout_user(user_id)
        return json_response(response.text, 200)


@user_ns.route("/<username>")
class UserDetails(Resource):
    @user_ns.doc(body=model)
    @oidc.accept_token(require_token=True)
    def put(self, username):
        """Update a user"""
        data = get_request_data(request)
        updated_user = keycloak_client.update_user_properties(username, **data)
        if updated_user:
            return jsonify(updated_user)
        else:
            return json_response(
                "Cannot update '{0}' properties. Check if client exists or properties are valid".format(
                    username
                ),
                400,
            )


if __name__ == "__main__":
    print("** Debug mode should never be used in a production environment! ***")
    app.run(
        host="0.0.0.0",
        ssl_context=(certificate_file, privatekey_file),
        port=8080,
        debug=True,
    )
