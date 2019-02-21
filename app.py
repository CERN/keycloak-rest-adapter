#!/usr/bin/env python

import json
import sys
import os
from xml.etree import ElementTree as ET

from ConfigParser import ConfigParser
from flask import Flask, make_response
from flask_oidc import OpenIDConnect
from flask_restful import Resource, Api, request
from keycloak_api_client.keycloak import KeycloakAPIClient


config_dir = os.getcwd()
privatekey_file = "{0}/config/keycloak-rest-adapter_nopass.key".format(config_dir)
certificate_file = "{0}/config/keycloak-rest-adapter.crt".format(config_dir)
keycloakclient_config_file = '{0}/config/keycloak_client.cfg'.format(config_dir)
flask_oidc_client_secrets_file = '{0}/config/flask_oidc_config.json'.format(
    config_dir)

default_openid_protocol_mappers_file = '{0}/config/client_protocol_mappers.json'.format(
    config_dir)

API_VERSION = 1.0
API_URL_PREFIX = '/api/v%s' % API_VERSION

app = Flask(__name__)
api = Api(app)

app.config.update({
    'SECRET_KEY': 'WHATEVER',
    'TESTING': True,
    'DEBUG': True,
    'OIDC-SCOPES': ['openid'],
    'OIDC_CLIENT_SECRETS': flask_oidc_client_secrets_file,
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_OPENID_REALM': 'master',
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_RESOURCE_SERVER_ONLY': True,
})

oidc = OpenIDConnect(app)


##################################
# not very elengant, see ->
# https://stackoverflow.com/questions/25925217/object-oriented-python-with-flask-server/25925286

config = ConfigParser()
config.readfp(open(keycloakclient_config_file))

keycloak_server = config.get("keycloak", "server")
realm = config.get("keycloak", "realm")
admin_user = config.get("keycloak", "admin_user")
admin_password = config.get("keycloak", "admin_password")
client_id = config.get("keycloak", "keycloak-rest-adapter-client")
client_secret = config.get(
            "keycloak", "keycloak-rest-adapter-client-secret")
ssl_cert_path = config.get("keycloak", "ssl_cert_path")

keycloak_client = KeycloakAPIClient(keycloak_server, realm, admin_user, admin_password, client_id, client_secret, ssl_cert_path)

def json_response(data='', status=200, headers=None):
    JSON_MIME_TYPE = 'application/json'
    headers = headers or {}
    if 'error' or 'error_description' in data:
        status = 400
    if 'Content-Type' not in headers:
        headers['Content-Type'] = JSON_MIME_TYPE
    return make_response(data, status, headers)


def get_request_data(request):
    # https://stackoverflow.com/questions/10434599/how-to-get-data-received-in-flask-request/25268170
    return request.form.to_dict() if request.form else request.get_json()

def is_xml(data):
   """
   Check if string is XML or not by trying to parse it
   """
   try:
       ET.fromstring(data)
       return True
   except ET.ParseError:
       return False

class Client(Resource):

    @app.route('{0}/client/token-exchange-permissions'.format(API_URL_PREFIX), methods=['POST'])
    def client_token_exchange_permissions():
        data = get_request_data(request)
        if not data or 'target' not in data or 'requestor' not in data:
            return json_response(
                "The request is missing 'target' or 'requestor'. They must be passed as a query parameter",
                400)
        target_client_name = data['target']
        requestor_client_name = data['requestor']

        target_client = keycloak_client.get_client_by_clientID(
            target_client_name)
        requestor_client = keycloak_client.get_client_by_clientID(
            requestor_client_name)
        if target_client and requestor_client:
            ret = keycloak_client.grant_token_exchange_permissions(
                target_client['id'], requestor_client['id'])
            return ret.reason
        else:
            return json_response(
                "Verify '{0}' and '{1}' exist".format(
                    target_client_name, requestor_client_name),
                400)

    @app.route('{0}/client/<clientId>'.format(API_URL_PREFIX), methods=['PUT'])
    @oidc.accept_token(require_token=True)
    def client_update(clientId):
        data = get_request_data(request)
        updated_client = keycloak_client.update_client_properties(clientId, **data)
        if updated_client:
            return json_response(json.dumps(updated_client), 200)
        else:
            return json_response(
                "Cannot update '{0}' properties. Check if client exists or properties are valid".format(clientId),
                400)

    @app.route('{0}/client'.format(API_URL_PREFIX), methods=['POST'])
    @app.route('{0}/client/<protocol>'.format(API_URL_PREFIX), methods=['POST'])
    @oidc.accept_token(require_token=True)
    def client_create(protocol=None):
        supported_protocols = ['saml', 'openid']
        data = get_request_data(request)
        if protocol:
            if protocol not in supported_protocols:
                return json_response(
                    "Client protocol type '{0}' not suported. Chose between '{1}'".format(protocol, supported_protocols),
                    404)
            else:
                data['protocol'] = protocol
        else:
            if is_xml(data['clientId']):
                # if data looks like XML use the client description converteri to create client
                new_client = keycloak_client.client_description_converter(data['clientId'])
            else:
                # no clientId nor protocol --> return error
                if not data or 'clientId' not in data or 'protocol' not in data:
                    return json_response(
                        "The request is missing the 'clientId' or 'protocol'. They must be passed as a query parameter.",
                        400)
                if data['protocol'] == "openid" and 'protocolMappers' not in data:
                    with open(default_openid_protocol_mappers_file) as f:
                        default_openid_protocol_mappers = json.load(f)
                    data['protocolMappers'] = default_openid_protocol_mappers['protocolMappers']

                new_client = keycloak_client.create_new_client(**data)
        return new_client.text


    @app.route('{0}/client/openid/<clientId>/regenerate-secret'.format(API_URL_PREFIX), methods=['POST'])
    @oidc.accept_token(require_token=True)
    def client_regenerate_secret(clientId):
        ret = keycloak_client.regenerate_client_secret(clientId)
        if ret:
            return json_response(ret.text, 200)
        else:
            return json_response(
                "Cannot reset '{0}' secret. Client not found".format(clientId),
                404)

    @app.route('{0}/client/<clientId>'.format(API_URL_PREFIX), methods=['DELETE'])
    @app.route('{0}/client/saml/<clientId>'.format(API_URL_PREFIX), methods=['DELETE'])
    @app.route('{0}/client/openid/<clientId>'.format(API_URL_PREFIX), methods=['DELETE'])
    @oidc.accept_token(require_token=True)
    def client_delete(clientId):
        ret = keycloak_client.delete_client_by_clientID(clientId)
        if ret:
            return json_response(
                "Client '{0}' deleted succesfully".format(clientId),
                200)
        else:
            return json_response(
                "Cannot delete client '{0}'. Client not found".format(clientId),
                404)

if __name__ == '__main__':
    print("** Debug mode should never be used in a production environment! ***")
    app.run(
        host='0.0.0.0',
        ssl_context=(
            certificate_file,
            privatekey_file),
        port=8080,
        debug=True)
