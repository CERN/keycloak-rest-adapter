from urllib.parse import urlparse
import re
from copy import deepcopy
from flask import current_app
from log_utils import configure_logging
import json


class ClientTypes:
    SAML = "saml"
    OIDC = "openid"


class Client:
    type = None
    definition = None
    scopes = []
    client_defaults = None
    partial_definition = False
    max_string_size = 255

    def init_app(self, app=None):
        """Initialize the application object for this client"""
        if app is None:
            app = current_app
        self.client_defaults = app.config["CLIENT_DEFAULTS"]
        self.logger = configure_logging(app.config["LOG_DIR"])

    def __init__(self, client_definition=None, protocol=ClientTypes.OIDC, client_id=None, app=None, partial_definition=False):
        """Constructor. Keyword arguments:
                - client_definition: the client will be constructed and adapted from the definition.
                - client_id: useful for stub clients.
                - protocol: it overrides the protocol from the definition.
                - app: specify an application object for this object. If None, current_app will be used.
                - partial_definition: when set to True, the empty fields won't be initialized. This is used for updating existing clients.
        """
        self.init_app(app)
        self.type = protocol
        self.partial_definition = partial_definition
        if client_definition is None:
            # Allow creating stub clients with just a client_id
            self.definition = {"clientId": client_id}
        else:
            self.definition = client_definition
            self.adapt_definition()

    def __str__(self):
        return "type' :{}, definition: {}".format(self.type, self.definition)

    def adapt_definition(self):
        """Modify the client definition to adapt it to the Keycloak format"""
        if self.type == ClientTypes.SAML:
            self.definition["protocol"] = "saml"
            self.__set_default_saml_signature()
            self.__set_default_saml_encryption()
        if self.type == ClientTypes.OIDC:
            self.definition["protocol"] = "openid-connect"
            if not self.partial_definition:
                self.__include_oidc_protocol_mapper()
            if not self.partial_definition and "publicClient" not in self.definition:
                self.definition["publicClient"] = False
        if not self.partial_definition and "redirectUris" not in self.definition:
            self.definition["redirectUris"] = []
        if not self.partial_definition and "attributes" not in self.definition:
            self.definition["attributes"] = {}
        if "description" in self.definition:  # The maximum description size is shorter in Keycloak than in the Authorization Service
            self.__truncate_string_field("description")

    def update_definition(self, new_definition):
        """Update the definition. The old definition will be merged and replaced with the new values."""
        for key, value in new_definition.items():
            if key == "id":  # Skip the client GUID
                continue
            elif key in self.definition or key in ["description", "attributes"]:
                self.logger.debug("Changing value: {}".format(value))
                self.definition[key] = value
            else:
                self.logger.warning(
                    "'{0}' not a valid client property. Skipping...".format(key)
                )
        # This will set the SAML certificate and encryption fields to false, if they are not provided.
        if self.type == ClientTypes.SAML:
            self.__set_default_saml_signature()
            self.__set_default_saml_encryption()

    def merge_definition_and_defaults(self):
        """ Merges the current definition on top of the defaults, if the object is
        a list or dict the request object will be appended, otherwise overwritten
        """
        defaults = self.client_defaults[self.type]
        output = deepcopy(defaults)
        for k in self.definition:
            if k in output and isinstance(self.definition[k], list):
                tmp_set_output = set(map(json.dumps, output[k]))
                tmp_set_definition = set(map(json.dumps, self.definition[k]))
                tmp_set_output.update(tmp_set_definition)
                output[k] = list(map(json.loads, tmp_set_output))
            elif k in output and isinstance(self.definition[k], dict):
                output[k].update(self.definition[k])
            else:
                output[k] = self.definition[k]
        self.definition = output

    def get_saml_signing_certificate(self):
        if self.definition.get("attributes"):
            return self.definition["attributes"].get("saml.signing.certificate")
        else:
            return None

    def get_saml_encryption_certificate(self):
        if self.definition.get("attributes"):
            return self.definition["attributes"].get("saml.encryption.certificate")
        else:
            return None

    def __set_default_saml_signature(self):
        # AuthnRequestsSigned attribute is not being correctly parsed by keycloak
        # If there is no signing certificate, set the clientCertificateRequired attribute to False
        if (
            self.definition.get("attributes")
            and self.definition["attributes"].get("saml.signing.certificate")
            is None
        ):
            self.definition["attributes"]["saml.client.signature"] = "false"

    def __set_default_saml_encryption(self):
        # This is the same case as with the SAML signature
        if (
            self.definition.get("attributes")
            and self.definition["attributes"].get("saml.encryption.certificate")
            is None
        ):
            self.definition["attributes"]["saml.encrypt"] = "false"

    def __include_oidc_protocol_mapper(self):
        if "protocolMappers" not in self.definition:
            self.definition["protocolMappers"] = []
            self.definition["protocolMappers"].append(
                self.__oidc_protocol_mapper()
            )

    def __oidc_protocol_mapper(self):
        """
        Creates the protocol mapper for OIDC
        """
        return {
            "protocol": "openid-connect",
            "config": {
                "id.token.claim": "false",
                "access.token.claim": "true",
                "included.client.audience": self.definition.get("clientId"),
            },
            "name": "audience",
            "protocolMapper": "oidc-audience-mapper",
        }

    def __truncate_string_field(self, field_name):
        if len(self.definition[field_name]) > self.max_string_size:
            self.definition[field_name] = self.definition[field_name][:self.max_string_size - 2] + '..'
