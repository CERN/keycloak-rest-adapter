import json
import os
from configparser import ConfigParser

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    request,
    send_from_directory,
)
from flask_restplus import Resource, Api, fields, apidoc

from auth import oidc_validate
from keycloak_api_client.keycloak import KeycloakAPIClient
from log_utils import configure_logging
from utils import (
    json_response,
    get_request_data,
    is_xml,
    validate_protocol,
    validate_protocol_data,
    config_dir,
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

API_VERSION = "v1.0"
API_URL_PREFIX = "/api/{}".format(API_VERSION)

##################################
# not very elengant, see ->
# https://stackoverflow.com/questions/25925217/object-oriented-python-with-flask-server/25925286

config = ConfigParser()
config.readfp(open(keycloakclient_config_file))

keycloak_server = config.get("keycloak", "server")
realm = config.get("keycloak", "realm")
client_id = config.get("keycloak", "keycloak_rest_adapter_client")
client_secret = config.get("keycloak", "keycloak_rest_adapter_client_secret")

keycloak_client = KeycloakAPIClient(keycloak_server, realm, client_id, client_secret)

ui_authorization_url = config.get("oauth", "auth_url", fallback=None)
if not ui_authorization_url:
    ui_authorization_url = "{0}/auth/realms/{1}/protocol/openid-connect/auth".format(
        keycloak_server, realm
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

app.logger = configure_logging()


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

# OIDC configuration
app.config.update(
    {
        "OIDC_JWKS_URL": config.get("oidc", "jwks_url"),
        "OIDC_ISSUER": config.get("oidc", "issuer"),
        "OIDC_CLIENT_ID": client_id,
    }
)


@app.route("/")
def index():
    return redirect("/swagger-ui")


@app.route("/oauth2-redirect.html")
def redirect_oauth():
    return send_from_directory("static", "oauth2-redirect.html")


@ns.route(
    "/openid/<path:target_client_id>/token-exchange-permissions/<path:requestor_client_id>"
)
class TokenExchangePermissions(Resource):
    @oidc_validate
    def put(self, target_client_id, requestor_client_id):
        """Grants token exchange permissions"""

        target_client = keycloak_client.get_client_by_clientID(target_client_id)
        requestor_client = keycloak_client.get_client_by_clientID(requestor_client_id)

        verify_error = self.__verify_clients(
            target_client, requestor_client, target_client_id, requestor_client_id
        )
        if verify_error:
            return verify_error

        ret = keycloak_client.grant_token_exchange_permissions(
            target_client, requestor_client
        )
        if ret.status_code == 200 or ret.status_code == 201:
            return ret.reason, 200
        else:
            return ret.reason, 400

    @oidc_validate
    def delete(self, target_client_id, requestor_client_id):
        """Revokes token exchange permissions"""
        target_client = keycloak_client.get_client_by_clientID(target_client_id)
        requestor_client = keycloak_client.get_client_by_clientID(requestor_client_id)

        verify_error = self.__verify_clients(
            target_client, requestor_client, target_client_id, requestor_client_id
        )
        if verify_error:
            return verify_error
        try:
            ret = keycloak_client.revoke_token_exchange_permissions(
                target_client, requestor_client
            )
        except ValueError as e:
            return e.args[0], 404
        if ret.status_code == 200 or ret.status_code == 201:
            return "Deleted", 200
        else:
            return ret.reason, 400

    def __verify_clients(
        self, target_client, requestor_client, target_client_name, requestor_client_name
    ):
        if target_client and requestor_client:
            return False
        else:
            return json_response(
                "Verify '{0}' and '{1}' exist".format(
                    target_client_name, requestor_client_name
                ),
                404,
            )


@ns.route("/<protocol>/<path:clientId>")
class ClientDetails(Resource):
    @ns.doc(body=model)
    @oidc_validate
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

    @oidc_validate
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


@ns.route("/openid/<string:clientId>/client-secret")
class ManageClientSecret(Resource):
    @oidc_validate
    def get(self, clientId):
        """Show current client secret"""
        ret = keycloak_client.display_client_secret(clientId)
        if ret:
            return jsonify(ret.json())
        else:
            return json_response(
                "Cannot display '{0}' secret. Client not found".format(clientId), 404
            )

    @oidc_validate
    def post(self, clientId):
        """Reset client secret"""
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
                with open(
                    "{0}/client_{1}_defaults.json".format(config_dir, protocol)
                ) as f:
                    saml_defaults = json.load(f)
                client_description["protocolMappers"] = saml_defaults["protocolMappers"]
                new_client = keycloak_client.create_new_client(**client_description)
            elif protocol == "openid":
                with open(
                    "{0}/client_{1}_defaults.json".format(config_dir, protocol)
                ) as f:
                    openid_defaults = json.load(f)
                if "protocolMappers" not in data:
                    # if not protocolMappers load default openid protocol mappers
                    data["protocolMappers"] = openid_defaults["protocolMappers"]
                    # include audience mapper with clientId
                    data["protocolMappers"].append(
                        {
                            "protocol": "openid-connect",
                            "config": {
                                "id.token.claim": "false",
                                "access.token.claim": "true",
                                "included.client.audience": data["clientId"],
                            },
                            "name": "audience",
                            "protocolMapper": "oidc-audience-mapper",
                        }
                    )
                if "webOrigins" not in data:
                    # include default web origins
                    data["webOrigins"] = openid_defaults["webOrigins"]
                new_client = keycloak_client.create_new_client(**data)
            else:
                return json_response(
                    "Unsupported client protocol '{}'".format(protocol), 400
                )
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
    @oidc_validate
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
    @oidc_validate
    def post(self):
        data = get_request_data(request)
        validation = validate_protocol_data(data)
        if validation:
            return validation
        return self.common_create(data)


@user_ns.route("/logout/<string:user_id>")
class UserLogout(Resource):
    @oidc_validate
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
    @oidc_validate
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
        # ssl_context=(certificate_file, privatekey_file),
        port=8080,
        debug=True,
    )
