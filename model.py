
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
    internal_domains_regex = None
    external_scope_oidc = None
    external_scope_saml = None
    client_defaults = None

    def init_app(self, app=None):
        """Initialize the application object for this client"""
        if app is None:
            app = current_app
        self.internal_domains_regex = app.config["INTERNAL_DOMAINS_REGEX"]
        self.external_scope_oidc = app.config["EXTERNAL_SCOPE_OIDC"]
        self.external_scope_saml = app.config["EXTERNAL_SCOPE_SAML"]
        self.client_defaults = app.config["CLIENT_DEFAULTS"]

    def __init__(self, client_definition=None, protocol=ClientTypes.OIDC, client_id=None, app=None):
        """Constructor. Keyword arguments:
                - client_definition: the client will be constructed and adapted from the definition.
                - client_id: useful for stub clients.
                - protocol: it overrides the protocol from the definition.
                - app: specify an application object for this object. If None, current_app will be used.
        """
        self.init_app(app)
        self.logger = configure_logging()
        self.type = protocol
        if self.internal_domains_regex is not None:
            self.internal_domains_regex = re.compile(self.internal_domains_regex)
        if client_definition is None:
            # Allow creating stub clients with just a client_id
            self.definition = {"clientId": client_id}
        else:
            self.definition = client_definition
            self.adapt_definition()

    def adapt_definition(self):
        """Modify the client definition to adapt it to the Keycloak format"""
        self.__merge_definition_and_defaults()
        self.__detect_and_assign_external_scope()
        if self.type == ClientTypes.SAML:
            self.__set_saml_signature()
            self.definition["protocol"] = "saml"
        if self.type == ClientTypes.OIDC:
            self.__include_oidc_protocol_mapper()
            if "publicClient" not in self.definition:
                self.definition["publicClient"] = False
            self.definition["protocol"] = "openid-connect"
        if "redirectUris" not in self.definition:
            self.definition["redirectUris"] = []
        if "attributes" not in self.definition:
            self.definition["attributes"] = {}

    def update_definition(self, new_definition):
        """Update the definition. The old definition will be merged and replaced with the new values."""
        is_external = False
        original_scopes = deepcopy(self.definition["defaultClientScopes"])
        for key, value in new_definition.items():
            if key in self.definition or key == "description":
                self.logger.debug("Changing value: {}".format(value))
                self.definition[key] = value
            else:
                self.logger.warn(
                    "'{0}' not a valid client property. Skipping...".format(key)
                )
            if key == 'redirectUris':
                is_external = self.__redirects_outside_cern()
            if is_external:
                self.definition['consentRequired'] = True
                external_scope = self.external_scope_oidc
                if self.definition['protocol'] == 'saml':
                    external_scope = self.external_scope_saml
                if 'defaultClientScopes' in self.definition:
                    self.definition['defaultClientScopes'].append(external_scope)
                    self.definition['defaultClientScopes'].extend(original_scopes)
                else:
                    self.definition['defaultClientScopes'] = original_scopes + [external_scope]

    def __set_saml_signature(self):
        # AuthnRequestsSigned attribute is not being correctly parsed by keycloak
        # If there is no signing certificate, set the clientCertificateRequired attribute to False
        if (
            self.definition.get("attributes")
            and self.definition["attributes"].get("saml.signing.certificate")
            is None
        ):
            self.definition["attributes"]["saml.client.signature"] = "false"

    def __redirects_outside_cern(self) -> bool:
        """ Sees whether at least one of the redirect Uris goes outside
        CERN or localhost. In this case, assume that the CERN or localhost
        redirects are used for testing within CERN.
        """
        redirects = self.definition.get("redirectUris")
        if redirects:
            p = re.compile(self.internal_domains_regex)
            for redirect in redirects:
                try:
                    hostname = urlparse(redirect).hostname
                    if not p.search(hostname):
                        return True
                except (AttributeError, TypeError):
                    # Could be a native app hostname
                    if not redirect.startswith("ch.cern"):
                        return True
            # No external redirect found
            return False
        else:
            return False

    def __merge_definition_and_defaults(self):
        """ Merges the current definition on top of the defaults, if the object is
        a list the request object will be appended, otherwise overwritten
        """
        defaults = self.client_defaults[self.type]
        output = deepcopy(defaults)
        for k in self.definition:
            if k in output and isinstance(self.definition[k], list):
                tmp_set_output = set(map(json.dumps, output[k]))
                tmp_set_definition = set(map(json.dumps, self.definition[k]))
                tmp_set_output.update(tmp_set_definition)
                output[k] = list(map(json.loads, tmp_set_output))
            else:
                output[k] = self.definition[k]
        self.definition = output

    def __detect_and_assign_external_scope(self):
        if self.__redirects_outside_cern():
            self.definition["consentRequired"] = True
            if 'defaultClientScopes' not in self.definition:
                self.definition['defaultClientScopes'] = []
            if self.type == ClientTypes.SAML:
                self.definition['defaultClientScopes'].append(current_app.config["EXTERNAL_SCOPE_SAML"])
            else:
                self.definition['defaultClientScopes'].append(current_app.config["EXTERNAL_SCOPE_OIDC"])

    def __include_oidc_protocol_mapper(self):
        if "protocolMappers" not in self.definition:
            self.definition["protocolMappers"] = {}
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
