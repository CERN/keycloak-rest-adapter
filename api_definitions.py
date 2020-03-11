from copy import deepcopy

from flask import (
    jsonify,
    request,
    current_app)
from flask_restplus import Resource, fields

from app import application
from app import api
from auth import oidc_validate_api, oidc_validate_user_or_api
from keycloak_api_client.keycloak import KeycloakAPIClient
from utils import (
    json_response,
    get_request_data,
    is_xml,
    validate_protocol,
    validate_protocol_data,
    ResourceNotFoundError,
)

keycloak_client: KeycloakAPIClient = application.config['KEYCLOAK_CLIENT']
ns = api.namespace("client", description="Client operations")
user_ns = api.namespace("user", description="Methods for handling user operations")

# Models
model = ns.model("Client", {"clientId": fields.String}, required=False)
user_model = user_ns.model(
    "User",
    {
        "username": fields.String,
        "enabled": fields.Boolean,
        "totp": fields.Boolean,
        "emailVerified": fields.Boolean,
        "firstName": fields.String,
        "lastName": fields.String,
        "email": fields.String,
    },
)


@ns.route(
    "/openid/<path:target_client_id>/token-exchange-permissions/<path:requestor_client_id>"
)
class TokenExchangePermissions(Resource):
    @oidc_validate_api
    def put(self, target_client_id, requestor_client_id):
        """Grants token exchange permissions"""

        target_client = keycloak_client.get_client_by_client_id(target_client_id)
        requestor_client = keycloak_client.get_client_by_client_id(requestor_client_id)

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

    @oidc_validate_api
    def delete(self, target_client_id, requestor_client_id):
        """Revokes token exchange permissions"""
        target_client = keycloak_client.get_client_by_client_id(target_client_id)
        requestor_client = keycloak_client.get_client_by_client_id(requestor_client_id)

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


@ns.route("/<protocol>/<path:client_id>")
class ClientDetails(Resource):

    def __init__(self, *args, **kwargs):
        super(ClientDetails, self).__init__(*args, **kwargs)
        self.auth_protocols = api.app.config['AUTH_PROTOCOLS']

    @ns.doc(body=model)
    @oidc_validate_api
    def put(self, protocol, client_id):
        """Update a client"""
        data = get_request_data(request)
        if (protocol == "saml") and ("definition" in data):
            data = keycloak_client.client_description_converter(data["definition"])
        updated_client = keycloak_client.update_client_properties(client_id, **data)
        if updated_client:
            return jsonify(updated_client)
        else:
            return json_response(
                "Cannot update '{0}' properties. Check if client exists or properties are valid".format(
                    client_id
                ),
                400,
            )

    @oidc_validate_api
    def delete(self, protocol, client_id):
        """Delete a client"""
        validation = validate_protocol(protocol, self.auth_protocols)
        if validation:
            return validation
        deletion_response = keycloak_client.delete_client_by_client_id(client_id)
        if deletion_response is not None:
            return json_response(
                "Client '{0}' deleted successfully".format(client_id), 200
            )
        else:
            return json_response(
                "Cannot delete client '{0}'. Client not found".format(client_id), 404
            )


@ns.route("/openid/<string:client_id>/client-secret")
class ManageClientSecret(Resource):
    @oidc_validate_api
    def get(self, client_id):
        """Show current client secret"""
        ret = keycloak_client.display_client_secret(client_id)
        if ret:
            return jsonify(ret.json())
        else:
            return json_response(
                "Cannot display '{0}' secret. Client not found".format(client_id), 404
            )

    @oidc_validate_api
    def post(self, client_id):
        """Reset client secret"""
        ret = keycloak_client.regenerate_client_secret(client_id)
        if ret:
            return jsonify(ret.json())
        else:
            return json_response(
                "Cannot reset '{0}' secret. Client not found".format(client_id), 404
            )


class CommonCreator(Resource):
    def __init__(self, *args, **kwargs):
        super(CommonCreator, self).__init__(*args, **kwargs)
        self.protocol_mappers = current_app.config['CLIENT_DEFAULTS']
        self.auth_protocols = current_app.config['AUTH_PROTOCOLS']

    def _create_oidc_protocol_mapper(self, data):
        """
        Creates the protocol mapper for OIDC
        """
        return {
            "protocol": "openid-connect",
            "config": {
                "id.token.claim": "false",
                "access.token.claim": "true",
                "included.client.audience": data["clientId"],
            },
            "name": "audience",
            "protocolMapper": "oidc-audience-mapper",
        }

    def common_create(self, data):
        """
        Common create method for all the endpoints
        """
        protocol = data["protocol"]
        selected_protocol_id = deepcopy(self.auth_protocols[protocol])
        if selected_protocol_id in data:
            if is_xml(data[selected_protocol_id]):
                # if data looks like XML use the client description converter to create client
                client_description = keycloak_client.client_description_converter(
                    data[selected_protocol_id]
                )
                # load saml protocol mappers
                saml_defaults = deepcopy(self.protocol_mappers[protocol])
                client_description.update(saml_defaults)
                new_client = keycloak_client.create_new_client(**client_description)
            elif protocol == "openid":
                client_params = deepcopy(self.protocol_mappers[protocol])
                client_params.update(data)
                # Include the audience mapper by default
                if "protocolMappers" not in client_params:
                    client_params["protocolMappers"] = {}
                client_params["protocolMappers"].append(self._create_oidc_protocol_mapper(data))
                new_client = keycloak_client.create_new_client(**client_params)
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
    @oidc_validate_api
    def post(self, protocol):
        data = get_request_data(request)
        data["protocol"] = protocol
        validation = validate_protocol_data(data, self.auth_protocols)
        if validation:
            return validation
        return self.common_create(data)


@ns.route("/")
class Creator(CommonCreator):
    @ns.doc(body=model)
    @oidc_validate_api
    def post(self):
        data = get_request_data(request)
        validation = validate_protocol_data(data, self.auth_protocols)
        if validation:
            return validation
        return self.common_create(data)


@user_ns.route("/logout/<string:user_id>")
class UserLogout(Resource):
    @oidc_validate_api
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
    @user_ns.doc(body=user_model)
    @oidc_validate_api
    def put(self, username):
        """Update a user"""
        data = get_request_data(request)
        updated_user = keycloak_client.update_user_properties(
            username, keycloak_client.realm, **data
        )
        if updated_user:
            return jsonify(updated_user)
        else:
            return json_response(
                "Cannot update '{0}' properties. Check if client exists or properties are valid".format(
                    username
                ),
                400,
            )


@user_ns.route("/<username>/authenticator/otp")
class OTP(Resource):
    @oidc_validate_user_or_api
    def get(self, username):
        """Gets status of OTP credentials for a user"""
        try:
            is_enabled = keycloak_client.is_credential_enabled_for_user(
                username,
                keycloak_client.REQUIRED_ACTION_CONFIGURE_OTP,
                keycloak_client.CREDENTIAL_TYPE_OTP,
            )
            return json_response({"enabled": is_enabled})
        except ResourceNotFoundError as e:
            return str(e), 404

    @oidc_validate_user_or_api
    def post(self, username):
        """Enables and resets OTP credentials for a user"""
        keycloak_client.disable_otp_for_user(username)
        keycloak_client.enable_otp_for_user(username)
        return "OTP Enabled and Reset", 200

    @oidc_validate_user_or_api
    def delete(self, username):
        """Disables and removes OTP credentials for a user"""
        if keycloak_client.is_credential_enabled_for_user(
                username,
                keycloak_client.REQUIRED_ACTION_WEBAUTHN_REGISTER,
                keycloak_client.CREDENTIAL_TYPE_WEBAUTHN,
        ):
            keycloak_client.disable_otp_for_user(username)
            return "OTP Disabled", 200
        else:
            return "WebAuthn must be enabled first", 403


@user_ns.route("/<username>/authenticator/webauthn")
class WebAuthn(Resource):
    @oidc_validate_user_or_api
    def get(self, username):
        """Gets status of WebAuthn credentials for a user"""
        try:
            is_enabled = keycloak_client.is_credential_enabled_for_user(
                username,
                keycloak_client.REQUIRED_ACTION_WEBAUTHN_REGISTER,
                keycloak_client.CREDENTIAL_TYPE_WEBAUTHN,
            )
            return json_response({"enabled": is_enabled})
        except ResourceNotFoundError as e:
            return str(e), 404

    @oidc_validate_user_or_api
    def post(self, username):
        """Enables and resets WebAuthn credentials for a user"""
        keycloak_client.disable_webauthn_for_user(username)
        keycloak_client.enable_webauthn_for_user(username)
        return "WebAuthn Enabled and Reset", 200

    @oidc_validate_user_or_api
    def delete(self, username):
        """Disables and removes WebAuthn credentials for a user"""
        if keycloak_client.is_credential_enabled_for_user(
                username,
                keycloak_client.REQUIRED_ACTION_CONFIGURE_OTP,
                keycloak_client.CREDENTIAL_TYPE_OTP,
        ):
            keycloak_client.disable_webauthn_for_user(username)
            return "WebAuthn Disabled", 200
        else:
            return "OTP must be enabled first", 403
