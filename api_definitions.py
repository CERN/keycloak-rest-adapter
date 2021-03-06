import logging
from copy import deepcopy

from flask import current_app, jsonify, request
from flask_restx import Resource, fields, Api

from auth import auth_lib_helper
from keycloak_api_client.keycloak import keycloak_client
from utils import (ResourceNotFoundError, get_request_data, is_xml,
                   json_response, validate_protocol, validate_protocol_data)


api = Api(
    title="Keycloak Rest Adapter API",
    description="A simple Keycloak adapter for handling clients",
    security={'oauth2': ['api']},
    doc="/swagger-ui",
)


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
    @auth_lib_helper.oidc_validate_api
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

    @auth_lib_helper.oidc_validate_api
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
        except ValueError as error:
            return error.args[0], 404
        logging.info(ret.status_code)
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
    @auth_lib_helper.oidc_validate_api
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

    @auth_lib_helper.oidc_validate_api
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
    @auth_lib_helper.oidc_validate_api
    def get(self, client_id):
        """Show current client secret"""
        ret = keycloak_client.display_client_secret(client_id)
        if ret:
            return jsonify(ret.json())
        else:
            return json_response(
                "Cannot display '{0}' secret. Client not found".format(client_id), 404
            )

    @auth_lib_helper.oidc_validate_api
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
        except Exception:
            logging.exception("Unknown error creating client")
            return json_response(
                "Unknown error creating client: {}".format(new_client), 400
            )


@ns.route("/<string:protocol>")
class CreatorDetails(CommonCreator):
    @ns.doc(body=model)
    @auth_lib_helper.oidc_validate_api
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
    @auth_lib_helper.oidc_validate_api
    def post(self):
        data = get_request_data(request)
        validation = validate_protocol_data(data, self.auth_protocols)
        if validation:
            return validation
        return self.common_create(data)


@user_ns.route("/logout/<string:user_id>")
class UserLogout(Resource):
    @auth_lib_helper.oidc_validate_api
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
    @auth_lib_helper.oidc_validate_api
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

#
# Routes for MFA settings
#
# Routes are /<username>/authenticator/[method], where [method] = otp or webauthn
# GET    /<username>/authenticator/[method]       : determine if method is enabled for user
# POST   /<username>/authenticator/[method]       : enabled method for user
# DELETE /<username>/authenticator/[method]       : disable method for user
# POST   /<username>/authenticator/[method]/reset : resets method credentials for user (disables and enables method)


def is_otp_enabled(client, username):
    """
    Check if OTP is enabled for the user
    """
    return client.is_credential_enabled_for_user(
        username,
        client.REQUIRED_ACTION_CONFIGURE_OTP,
        client.CREDENTIAL_TYPE_OTP)


def is_webauthn_enabled(client, username):
    """
    Check if WebAuthN is enabled for the user
    """
    return client.is_credential_enabled_for_user(
        username,
        client.REQUIRED_ACTION_WEBAUTHN_REGISTER,
        client.CREDENTIAL_TYPE_WEBAUTHN)


@user_ns.route("/<username>/authenticator")
class MfaSettings(Resource):

    @auth_lib_helper.oidc_validate_user_or_api
    def get(self, username):
        """
        Gets all the MFA settings for the user
        """
        try:
            otp_enabled, otp_must_initialize, webauthn_enabled, webauthn_must_initialize = keycloak_client.get_user_mfa_settings(username)
            return json_response({
                "otp": {
                    "enabled": otp_enabled,
                    "initialization_required": otp_must_initialize
                },
                "webauthn": {
                    "enabled": webauthn_enabled,
                    "initialization_required": webauthn_must_initialize
                }
            })
        except ResourceNotFoundError as e:
            return str(e), 404


@user_ns.route("/<username>/authenticator/otp")
class OTP(Resource):

    @auth_lib_helper.oidc_validate_user_or_api
    def get(self, username):
        """Gets status of OTP credentials for a user"""
        try:
            is_enabled = is_otp_enabled(keycloak_client, username)
            return json_response({"enabled": is_enabled})
        except ResourceNotFoundError as e:
            return str(e), 404

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def post(self, username):
        """Enables OTP credentials for a user"""
        try:
            is_enabled = is_otp_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404

        if not is_enabled:
            keycloak_client.enable_otp_for_user(username)
            return "OTP Enabled", 200
        else:
            return "OTP already enabled", 200

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def delete(self, username):
        """Disables and removes OTP credentials for a user"""
        try:
            otp_enabled = is_otp_enabled(keycloak_client, username)
            webauthn_enabled = is_webauthn_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404
        if not otp_enabled:
            return "OTP already disabled", 200
        if not webauthn_enabled:
            return "Cannot disable OTP if WebAuthn is not enabled. At least one MFA method must always be enabled for the user.", 403
        keycloak_client.disable_otp_for_user(username)
        return "OTP Disabled", 200


@user_ns.route("/<username>/authenticator/otp/reset")
class OTPReset(Resource):

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def post(self, username):
        """Enables and resets OTP credentials for a user"""
        try:
            is_enabled = is_otp_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404
        if is_enabled:
            keycloak_client.disable_otp_for_user(username)
        keycloak_client.enable_otp_for_user(username)
        return "OTP Enabled and Reset", 200


@user_ns.route("/<username>/authenticator/webauthn")
class WebAuthn(Resource):
    @auth_lib_helper.oidc_validate_user_or_api
    def get(self, username):
        """Gets status of WebAuthn credentials for a user"""
        try:
            is_enabled = is_webauthn_enabled(keycloak_client, username)
            return json_response({"enabled": is_enabled})
        except ResourceNotFoundError as e:
            return str(e), 404

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def post(self, username):
        """Enables WebAuthn credentials for a user"""
        try:
            is_enabled = is_webauthn_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404
        if not is_enabled:
            keycloak_client.enable_webauthn_for_user(username)
            return "WebAuthn Enabled", 200
        else:
            return "WebAuthn already enabled", 200

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def delete(self, username):
        """Disables and removes WebAuthn credentials for a user"""
        try:
            otp_enabled = is_otp_enabled(keycloak_client, username)
            webauthn_enabled = is_webauthn_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404
        if not webauthn_enabled:
            return "WebAuthn already disabled", 200
        if not otp_enabled:
            return "Cannot disable WebAuthn if OTP is not enabled. At least one MFA method must always be enabled for the user.", 403
        keycloak_client.disable_webauthn_for_user(username)
        return "WebAuthn Disabled", 200


@user_ns.route("/<username>/authenticator/webauthn/reset")
class WebAuthnReset(Resource):

    @auth_lib_helper.oidc_validate_multifactor_user_or_api
    def post(self, username):
        """Enables and resets WebAuthn credentials for a user"""
        try:
            is_enabled = is_webauthn_enabled(keycloak_client, username)
        except ResourceNotFoundError as e:
            return str(e), 404
        if is_enabled:
            keycloak_client.disable_webauthn_for_user(username)
        keycloak_client.enable_webauthn_for_user(username)
        return "WebAuthn Enabled and Reset", 200
