#!/usr/bin/env python

import json
import logging
from typing import Dict, Any
from copy import deepcopy

import requests

from log_utils import configure_logging
from utils import ResourceNotFoundError


class KeycloakAPIClient:
    # To be investigated:
    # https://stackoverflow.com/questions/46470477/how-to-get-keycloak-users-via-rest-without-admin-account

    """
    KeycloakAPI Client to interact with the Keycloak API.
    """

    def init_app(self, app):
        """
        Initialize the adapter based on the app config
        """
        self._initialize(
            app.config['KEYCLOAK_SERVER'],
            app.config['KEYCLOAK_REALM'],
            app.config['KEYCLOAK_CLIENT_ID'],
            app.config['KEYCLOAK_CLIENT_SECRET']
        )

    def _initialize(self,
            server,
            realm,
            client_id,
            client_secret,
            master_realm="master",
            mfa_realm="mfa",):
        """
        Initialize the class with the params needed to use the API.
        server: keycloak server: ex. https://keycloak-server.cern.ch
        realm: realm name KeycloakAPI Client will interact with
        client_id: ex. keycloak-rest-adapter
        client_secret: client_id secret
        master_realm: master (needed it for admin API calls, admin token...)
        """
        self.keycloak_server = server
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.master_realm = master_realm
        self.mfa_realm = mfa_realm

        self.base_url = "{}/auth".format(self.keycloak_server)
        self.logger.info(
            "Client configured to talk to '{0}' server and realm '{1}'".format(
                self.keycloak_server, self.realm
            )
        )

        # danielfr quick hack, in non master realms "master-realm" client is replaced by "realm-management"
        if realm == "master":
            self.master_realm_client = self.get_client_by_client_id(
                "master-realm", self.realm
            )
        else:
            self.master_realm_client = self.get_client_by_client_id(
                "realm-management", self.realm
            )

    def __init__(self):
        self.keycloak_server = None
        self.realm = None
        self.client_id = None
        self.client_secret = None
        self.master_realm = None
        self.mfa_realm = None

        self.base_url = None
        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.logger = configure_logging()
        # Persistent SSL configuration
        # http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        self.session = requests.Session()

        # Keycloak constants
        self.CREDENTIAL_TYPE_OTP = "otp"
        self.CREDENTIAL_TYPE_WEBAUTHN = "webauthn"
        self.REQUIRED_ACTION_CONFIGURE_OTP = "CONFIGURE_TOTP"
        self.REQUIRED_ACTION_WEBAUTHN_REGISTER = "webauthn-register"
        self.access_token_object = None
        self.master_realm_client = None

    def __send_request(self, request_type, url, **kwargs):
        # if there is 'headers' in kwargs use it instead of default class one
        r_headers = deepcopy(self.headers)
        if "headers" in kwargs:
            r_headers.update(kwargs.pop("headers", None))

        method = getattr(self.session, request_type.lower(), None)
        if method:
            ret = method(url=url, headers=r_headers, **kwargs)
        else:
            raise Exception(
                "Specified request_type '{0}' not supported".format(request_type)
            )
        return ret

    def send_request(self, request_type, url, **kwargs):
        """ Call the private method __send_request and retry in case the access_token has expired"""
        try:
            ret = self.__send_request(request_type, url, **kwargs)
        except requests.exceptions.ConnectionError:
            msg = "Cannot process the request. Is the keycloak server down ('{0}')?".format(
                self.keycloak_server
            )
            self.logger.error(msg)
            raise Exception(msg)

        if ret.reason == "Unauthorized":
            self.logger.info("Admin token seems expired. Getting new admin token")
            self.access_token_object = self.get_admin_access_token()
            self.logger.info("Updating request headers with new access token")
            kwargs["headers"] = self.__get_admin_access_token_headers()
            return self.__send_request(request_type, url, **kwargs)
        else:
            return ret

    def __get_admin_access_token_headers(self):
        """
        Get HTTP headers with an admin bearer token
        """
        if self.access_token_object is None:
            # get admin access token for the 1st time
            self.access_token_object = self.get_admin_access_token()

        access_token = self.access_token_object["access_token"]
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(access_token),
        }

        return headers

    def set_client_fine_grain_permission(self, clientid, status):
        """
        Enable/disable fine grain permissions for the given client
        clientid: ID string of the client. E.g: 6781736b-e1f7-4ff7-a883-f4168c4dbd8a
        status: boolean value to enable/disable permissions
        """
        self.logger.info(
            "Setting client '{0}' fine grain permissions to '{1}'".format(
                clientid, status
            )
        )
        headers = self.__get_admin_access_token_headers()
        data = {"enabled": status}
        url = "{0}/admin/realms/{1}/clients/{2}/management/permissions".format(
            self.base_url, self.realm, clientid
        )

        ret = self.send_request("put", url, headers=headers, data=json.dumps(data))
        return ret

    def create_client_mapper(self, client_id, **kwargs):
        """
        Create client mapper.
        kwargs: Each protocol mappers has different values.
        Example of expected 'oidc-usermodel-attribute-mapper' mapper
        {
          config:  {
            access.token.claim:		<bool>,
            aggregate.attrs:		<bool>,
            claim.name:	        	<string>,
            id.token.claim:		<bool>,
            jsonType.label:		<type>,
            multivalued:	       	<bool>,
            user.attribute:		<string>,
            userinfo.token.claim:	<bool>,
          }
        name:			<string>,
        protocol:		openid-connect,
        protocolMapper:		oidc-usermodel-attribute-mapper
        }
        """
        headers = self.__get_admin_access_token_headers()
        self.logger.info(
            "Creating mapper with the following configuration: {0}".format(kwargs)
        )
        client_object = self.get_client_by_client_id(client_id)
        if client_object:
            url = "{0}/admin/realms/{1}/clients/{2}/protocol-mappers/models".format(
                self.base_url, self.realm, client_object["id"]
            )
            ret = self.send_request(
                "post", url, data=json.dumps(kwargs), headers=headers
            )
            return ret
        else:
            self.logger.info(
                "Cannot update client '{0}' mappers. Client not found".format(client_id)
            )
            return

    def update_client_mappers(self, client_id, mapper_name, **kwargs):
        """
        Update client mapper
        kwargs: Only the following mapper attributes can be modified.
        --> access.token.claim: <bool>,   claim.name:           <string>
        --> id.token.claim:	<bool>,   jsonType.label:	<type>
        --> user.attribute:	<string>, userinfo.token.claim: <bool>
        """
        headers = self.__get_admin_access_token_headers()
        self.logger.info(
            "Updating mapper with the following configuration: {0}".format(kwargs)
        )
        client_object = self.get_client_by_client_id(client_id)
        if client_object:
            if "protocolMappers" in client_object:
                for mapper in client_object["protocolMappers"]:
                    if mapper["name"] == mapper_name:
                        url = "{0}/admin/realms/{1}/clients/{2}/protocol-mappers/models/{3}".format(
                            self.base_url, self.realm, client_object["id"], mapper["id"]
                        )
                        updated_mapper = mapper
                        for key in kwargs:
                            if key in mapper["config"]:
                                updated_mapper["config"][key] = kwargs[key]
                            else:
                                self.logger.error(
                                    "'{0}' not a valid mapper attribute. Mapper not updated".format(
                                        key
                                    )
                                )
                                return  # not update and return empty

                        ret = self.send_request(
                            "put", url, data=json.dumps(updated_mapper), headers=headers
                        )
                        return ret

                self.logger.info(
                    "Cannot mapper '{0}' for client '{1}'. Protocol mapper not found".format(
                        mapper_name, client_id
                    )
                )
                return

            else:
                self.logger.info(
                    "Cannot update client '{0}' mapper. Client mappers not found".format(
                        client_id
                    )
                )
                return
        else:
            self.logger.info(
                "Cannot update client '{0}' mappers. Client not found".format(client_id)
            )
            return

    def update_client_properties(self, client_id, **kwargs):
        """
        Update existing client properties
        kwargs: { "property_name": "new_value", ... , }
        Returns: Updated client object
        """
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_client_id(client_id)
        self.logger.info(
            "Updating client with the following new propeties: {0}".format(kwargs)
        )
        if client_object:
            url = "{0}/admin/realms/{1}/clients/{2}".format(
                self.base_url, self.realm, client_object["id"]
            )
            for key, value in kwargs.items():
                if key in client_object or key == "description":
                    self.logger.debug("Changing value: {}".format(value))
                    client_object[key] = value
                else:
                    self.logger.warn(
                        "'{0}' not a valid client property. Skipping...".format(key)
                    )

            self.send_request(
                "put", url, data=json.dumps(client_object), headers=headers
            )
            if "clientId" in kwargs:
                client_id = kwargs["clientId"]

            updated_client = self.get_client_by_client_id(client_id)
            self.logger.info(
                "Client '{0}' updated: {1}".format(client_id, updated_client)
            )
            return updated_client
        else:
            self.logger.info(
                "Cannot update client '{0}' properties. Client not found".format(
                    client_id
                )
            )
            return

    def client_description_converter(self, payload):
        """
        Create a new client via its client description (xml or json)
        payload: XML or JSON definition of the client
        Returns: Client description parsed as a dict
        """
        self.logger.info("Attempting to create new client via description converter...")
        headers = self.__get_admin_access_token_headers()

        url = "{0}/admin/realms/{1}/client-description-converter".format(
            self.base_url, self.realm
        )
        ret = self.send_request("post", url, headers=headers, data=payload)
        self.logger.info( "Converted to: '{0}'".format( ret.text ) )
        return json.loads(ret.text)

    def display_client_secret(self, client_id):
        """
        Show client secret of the given client
        """
        self.logger.info("Getting '{0}' secret...".format(client_id))
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_client_id(client_id)
        if client_object:
            if client_object["protocol"] == "openid-connect":
                url = "{0}/admin/realms/{1}/clients/{2}/client-secret".format(
                    self.base_url, self.realm, client_object["id"]
                )

                ret = self.send_request("get", url, headers=headers)
            else:
                ret = requests.Response  # new empty response
                ret.text = "Cannot display client '{0}' secret. Client not openid type".format(
                    client_id
                )
                self.logger.info(ret.text)
            return ret
        else:
            self.logger.info(
                "Cannot display client '{0}' secret. Client not found".format(client_id)
            )

    def regenerate_client_secret(self, client_id):
        """
        Regenerate client secret of the given client
        """
        self.logger.info("Attempting to regenerate '{0}' secret...".format(client_id))
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_client_id(client_id)
        if client_object:
            if client_object["protocol"] == "openid-connect":
                url = "{0}/admin/realms/{1}/clients/{2}/client-secret".format(
                    self.base_url, self.realm, client_object["id"]
                )

                ret = self.send_request("post", url, headers=headers)
                self.logger.info("Client '{0}' secret regenerated".format(client_id))
            else:
                ret = requests.Response  # new empty response
                ret.text = "Cannot regenerate client '{0}' secret. Client not openid type".format(
                    client_id
                )
                self.logger.info(ret.text)
            return ret
        else:
            self.logger.info(
                "Cannot regenerate client '{0}' secret. Client not found".format(
                    client_id
                )
            )

    def delete_client_by_client_id(self, client_id):
        """
        Delete client with the given clientID name
        """
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_client_id(client_id)
        if client_object:
            url = "{0}/admin/realms/{1}/clients/{2}".format(
                self.base_url, self.realm, client_object["id"]
            )

            ret = self.send_request("delete", url, headers=headers)
            self.logger.info("Deleted client '{0}'".format(client_id))
            return ret
        else:
            self.logger.info("Cannot delete '{0}'. Client not found".format(client_id))

    def get_client_by_client_id(self, client_id, realm=None) -> Dict[str, Any]:
        """
        Get the list of clients that match the given clientID name
        """
        if not realm:
            realm = self.realm
        headers = self.__get_admin_access_token_headers()
        payload = {"clientId": client_id, "viewable": True}
        url = "{0}/admin/realms/{1}/clients".format(self.base_url, realm)

        ret = self.send_request("get", url, headers=headers, params=payload)

        self.logger.info("Getting client '{0}' object".format(client_id))
        client = json.loads(ret.text)

        # keycloak returns a list of 1 element if found, empty if not
        if len(client) == 1:
            self.logger.info(
                "Found client '{0}' ({1})".format(client_id, client[0]["id"])
            )
            return client[0]
        else:
            self.logger.info("Client '{0}' NOT found".format(client_id))
            return client

    def get_client_policy_by_name(self, policy_name):
        """
        Get the list of client policies that match the given policy name
        """
        self.logger.info("Getting policy '{0}' object".format(policy_name))
        headers = self.__get_admin_access_token_headers()
        payload = {"name": policy_name}
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/policy".format(
            self.base_url, self.realm, self.master_realm_client["id"]
        )

        ret = self.send_request("get", url, headers=headers, params=payload)

        # keycloak returns a list of all matching policies
        matching_policies = json.loads(ret.text)
        if isinstance(matching_policies, dict):
            if 'error' in matching_policies:
                return []
        # return exact match
        return [policy for policy in matching_policies if policy["name"] == policy_name]

    def create_client_policy(
        self,
        clientid,
        policy_name,
        policy_description="",
        policy_logic="POSITIVE",
        policy_strategy="UNANIMOUS",
    ):
        """
        Create client policy for the given clientid
        clientid: ID string of the client. E.g: 6781736b-e1f7-4ff7-a883-f4168c4dbd8a
        """
        self.logger.info(
            "Creating policy new '{0}' for client {1}".format(policy_name, clientid)
        )
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/policy/client".format(
            self.base_url, self.realm, self.master_realm_client["id"]
        )

        self.logger.info("Checking if '{0}' already exists...".format(policy_name))
        client_policy = self.get_client_policy_by_name(policy_name)

        if len(client_policy) == 0:
            # create new policy
            self.logger.info(
                "It does not exist. Creating new policy and subscribing it to client '{0}'".format(
                    clientid
                )
            )
            http_method = "post"
            subscribed_clients = [clientid]

        else:
            # update already existing policy
            self.logger.info(
                "There is an exisintg policy with name {0}. Updating it to subscribe client '{1}'".format(
                    policy_name, clientid
                )
            )
            url = url + "/{0}".format(client_policy[0]["id"])
            http_method = "put"
            subscribed_clients = json.loads(client_policy[0]["config"]["clients"])
            subscribed_clients.append(clientid)

        data = {
            "clients": subscribed_clients,
            "name": policy_name,
            "type": "client",
            "description": policy_description,
            "logic": policy_logic,
            "decisionStrategy": policy_strategy,
        }

        ret = self.send_request(
            http_method, url, headers=headers, data=json.dumps(data)
        )
        return ret

    def get_auth_permission_by_name(self, permission_name):
        """
        Get REALM's authorization permission by name
        permission_name: authorization permission name to get
        ret: Matching Authorization permission object
        """
        self.logger.info(
            "Getting authorization permission '{0}' object".format(permission_name)
        )
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/permission/".format(
            self.base_url, self.realm, self.master_realm_client["id"]
        )

        payload = {"name": permission_name}
        ret = self.send_request("get", url, headers=headers, params=payload)
        return json.loads(ret.text)

    def get_auth_policy_by_name(self, policy_name):
        """
        Get REALM's authorization policies by name
        policy_name: authorization policy name to get
        ret: Matching Authorization policy object
        """
        self.logger.info("Getting authorization policy '{0}'".format(policy_name))
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/policy/".format(
            self.base_url, self.realm, self.master_realm_client["id"]
        )

        payload = {"name": policy_name}
        ret = self.send_request("get", url, headers=headers, params=payload)
        return ret

    def get_client_token_exchange_permission(self, clientid):
        """
        Get token-exchange permission for the client with given ID
        clientid: ID string of the client. E.g: 6781736b-e1f7-4ff7-a883-f4168c4dbd8a
        """
        self.logger.info(
            "Getting token-exhange permission for client '{0}'...".format(clientid)
        )
        token_exchange_permission_name = "token-exchange.permission.client.{0}".format(
            clientid
        )
        return self.get_auth_permission_by_name(token_exchange_permission_name)[0]

    def grant_token_exchange_permissions(
        self, target_client_object, requestor_client_object
    ):
        """
        Grant token-exchange permission for target client to destination client
        target_client_object: Object of the target client
        requestor_client_object: Object of the requestor client
        """
        requestor_clientid = requestor_client_object["clientId"]
        requestor_id = requestor_client_object["id"]
        target_clientid = target_client_object["clientId"]
        target_id = target_client_object["id"]

        self.set_client_fine_grain_permission(target_id, True)
        client_token_exchange_permission = self.get_client_token_exchange_permission(
            target_id
        )
        tep_associated_policies = self.get_permission_associated_policies(
            client_token_exchange_permission["id"]
        )
        policies = [policy["id"] for policy in tep_associated_policies]

        policy_name = "allow token exchange for {0}".format(requestor_clientid)
        policy_description = "Allow token exchange for '{0}' client".format(
            requestor_clientid
        )

        self.create_client_policy(requestor_id, policy_name, policy_description)
        policy = self.get_client_policy_by_name(policy_name)[0]

        self.logger.info(
            "Granting token-exhange between client '{0}' and '{1}'".format(
                target_clientid, requestor_clientid
            )
        )
        policies.append(policy["id"])
        return self.update_token_exchange_permissions(
            client_token_exchange_permission, policies
        )

    def revoke_token_exchange_permissions(
        self, target_client_object, requestor_client_object
    ):
        """
        Revoke token-exchange permission for target client to destination client
        target_client_object: Object of the target client
        requestor_client_object: Object of the requestor client
        """
        requestor_clientid = requestor_client_object["clientId"]
        requestor_id = requestor_client_object["id"]
        target_clientid = target_client_object["clientId"]
        target_id = target_client_object["id"]

        client_token_exchange_permission = self.get_client_token_exchange_permission(
            target_id
        )
        tep_associated_policies = self.get_permission_associated_policies(
            client_token_exchange_permission["id"]
        )
        policies = [policy["id"] for policy in tep_associated_policies]
        policy_name = "allow token exchange for {0}".format(requestor_clientid)
        policy = self.get_client_policy_by_name(policy_name)

        if len(policy) == 0:
            # policy not found. It might be using the old naming convention...
            policy_name_old = "allow token exchange for {0}".format(requestor_id)
            self.logger.info(
                "Policy '{0}' not found. Trying using the old naming convention '{1}'".format(
                    policy_name, policy_name_old
                )
            )
            policy = self.get_client_policy_by_name(policy_name_old)[0]
        else:
            policy = policy[0]

        try:
            policies.remove(policy["id"])
        except ValueError:
            raise ValueError(
                "Token exchange permissions not found between client '{0}' and '{1}'".format(
                    target_clientid, requestor_clientid
                )
            )
        self.logger.info(
            "Revoking token-exhange between client '{0}' and '{1}'".format(
                target_clientid, requestor_clientid
            )
        )
        return self.update_token_exchange_permissions(
            client_token_exchange_permission, policies
        )

    def update_token_exchange_permissions(
        self, client_token_exchange_permission, policies
    ):
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/permission/scope/{3}".format(
            self.base_url,
            self.realm,
            self.master_realm_client["id"],
            client_token_exchange_permission["id"],
        )
        # if permission associated with at least one policy --> decisionStrategy to AFFIRMATIVE instead of UNANIMOUS
        if len(policies) > 0:
            client_token_exchange_permission["decisionStrategy"] = "AFFIRMATIVE"

        client_token_exchange_permission["policies"] = policies
        ret = self.send_request(
            "put",
            url,
            headers=headers,
            data=json.dumps(client_token_exchange_permission),
        )
        return ret

    def get_permission_associated_policies(self, permission_id):
        """
        Gets all the policies associated to a permission
        :param permission_id: The ID of the permission
        """
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/policy/{3}/associatedPolicies".format(
            self.base_url, self.realm, self.master_realm_client["id"], permission_id
        )
        headers = self.__get_admin_access_token_headers()
        ret = self.send_request("get", url, headers=headers)
        return json.loads(ret.text)

    def get_all_clients(self):
        """
        Return list of clients
        """
        self.logger.info("Getting all clients")
        headers = self.__get_admin_access_token_headers()
        payload = {"viewableOnly": "true"}
        url = "{0}/admin/realms/{1}/clients".format(self.base_url, self.realm)
        ret = self.send_request("get", url, headers=headers, params=payload)
        # return clients as list of json instead of string
        return json.loads(ret.text)

    def get_admin_access_token(self):
        """
        https://www.keycloak.org/docs/2.5/server_development/topics/admin-rest-api.html
        """
        url = "{0}/realms/{1}/protocol/openid-connect/token".format(
            self.base_url, self.master_realm
        )

        grant_type = "client_credentials"
        payload = "scope=openid&grant_type={0}&client_id={1}&client_secret={2}".format(
            grant_type, self.client_id, self.client_secret
        )

        self.logger.info(
            "Getting admin access token using {} client credentials".format(
                self.client_id
            )
        )
        ret = self.send_request("post", url, data=payload)
        if ret.status_code != 200:
            self.logger.error(
                "Error occured while getting admin token: {}".format(ret.text)
            )
        return json.loads(ret.text)

    def get_access_token(self):
        """
        Return access_token using the configured client_id & secret
        """
        access_token_object = self.get_client_credentials_access_token(
            self.client_id, self.client_secret
        )
        access_token = access_token_object["access_token"]
        return access_token

    def get_client_credentials_access_token(self, client_id, client_secret):
        """ Return the access_token JSON object requested -> oauth2 Client Credentials grant.
        https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
        """
        grant_type = "client_credentials"

        url = "{0}/realms/{1}/protocol/openid-connect/token".format(
            self.base_url, self.master_realm
        )
        payload = "client_id={0}&grant_type={1}&client_secret={2}".format(
            client_id, grant_type, client_secret
        )
        r = self.send_request("post", url, data=payload)
        if r.status_code != 200:
            self.logger.error(
                "Error getting client credentials: {}, {}".format(r.status_code, r.text)
            )
        return json.loads(r.text)

    def get_token_exchange_request(
        self, client_id, client_secret, subject_token, audience
    ):
        """ Return an Authorization Code Exchange token JSON object -> oauth2 Authorization Code Exchange
        https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
        """
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
        subject_token_type = "urn:ietf:params:oauth:token-type:access_token"

        url = "{0}/realms/{1}/protocol/openid-connect/token".format(
            self.base_url, self.realm
        )
        payload = "client_id={0}&grant_type={1}&client_secret={2}&subject_token_type={3}&subject_token={4}&audience={5}".format(
            client_id,
            grant_type,
            client_secret,
            subject_token_type,
            subject_token,
            audience,
        )
        r = self.send_request("post", url, data=payload)
        return json.loads(r.text)

    def __create_client(self, access_token, **kwargs):
        """Private method for adding a new client.
        access_token: https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
        #_clientrepresentation
        kwargs: See the full list of available params: https://www.keycloak.org/docs-api/3.4/rest-api/index.html
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(access_token),
        }
        url = "{0}/admin/realms/{1}/clients".format(self.base_url, self.realm)
        self.logger.info(
            "Creating client '%s' --> %s", kwargs["clientId"], kwargs
        )
        return self.send_request("post", url, headers=headers, json=kwargs)

    def logout_user(self, user_id):
        """
        Logs out the user from all his sessions
        """
        url = "{0}/admin/realms/{1}/users/{2}/logout".format(
            self.base_url, self.realm, user_id
        )
        self.logger.info("Logging out user ID '{0}'".format(user_id))
        return self.send_request("post", url)

    def create_new_openid_client(self, **kwargs):
        """Add new OPENID client.
        kwargs: See the full list of available params: https://www.keycloak.org/docs-api/3.4/rest-api/index.html#_clientrepresentation
        """
        access_token = self.get_access_token()
        # load minimum default values to create OPENID-CONNECT client
        if "redirectUris" not in kwargs:
            kwargs["redirectUris"] = []
        if "attributes" not in kwargs:
            kwargs["attributes"] = {}
        # by default, create confidential client
        if "publicClient" not in kwargs:
            kwargs["publicClient"] = False
        if "protocol" not in kwargs or kwargs["protocol"] != "openid-connect":
            # on API level we accept 'openid-connect' & 'openid'. Keycloak only accepts 'openid-connect'
            kwargs["protocol"] = "openid-connect"
        response = self.__create_client(access_token, **kwargs)
        if response.ok:
            # Hack in order to set consent_required to false if it's actually specified, not just ignore it
            # See: https://www.keycloak.org/docs/latest/securing_apps/index.html#client-registration-policies
            # (Consent Required Policy) section
            update_response = self.update_client_properties(
                kwargs["clientId"], **kwargs
            )
            client_secret_json = self.display_client_secret(
                update_response["clientId"]
            ).json()
            update_response["secret"] = (
                client_secret_json["value"] if "value" in client_secret_json else None
            )
            return update_response
        return response.json()

    def create_new_saml_client(self, **kwargs):
        """Add new SAML client.
        kwargs: See the full list of available params: https://www.keycloak.org/docs-api/3.4/rest-api/index.html#_clientrepresentation
        """
        access_token = self.get_access_token()
        # load minimum default values to create SAML client
        if "redirectUris" not in kwargs:
            kwargs["redirectUris"] = []
        if "attributes" not in kwargs:
            kwargs["attributes"] = {}
        if "protocol" not in kwargs or kwargs["protocol"] != "saml":
            kwargs["protocol"] = "saml"
        response = self.__create_client(access_token, **kwargs)
        if response.ok:
            # Hack in order to set consent_required to false if it's actually specified, not just ignore it
            # See: https://www.keycloak.org/docs/latest/securing_apps/index.html#client-registration-policies
            # (Consent Required Policy) section
            return self.update_client_properties(kwargs["clientId"], **kwargs)
        return response.json()

    def create_new_client(self, **kwargs):
        """Add new client.
        kwargs: See the full list of available params: https://www.keycloak.org/docs-api/3.4/rest-api/index.html#_clientrepresentation
        """
        if "protocol" in kwargs:
            protocol = kwargs["protocol"]
            if protocol == "saml":
                return self.create_new_saml_client(**kwargs)
            elif protocol in ["openid-connect", "openid"]:
                return self.create_new_openid_client(**kwargs)

    def get_user_by_username(self, username, realm=None):
        """
        Get user by userID
        """
        if not realm:
            realm = self.realm
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/users?first=0&max=100&username={2}".format(
            self.base_url, realm, username
        )

        ret = self.send_request("get", url, headers=headers)

        self.logger.info("Getting user '{0}' object".format(username))
        found_users = json.loads(ret.text)

        for user in found_users:
            if user["username"] == username:
                self.logger.info("Found user '{0}' ({1})".format(username, user["id"]))
                return user

        self.logger.info("User '{0}' NOT found".format(username))
        raise ResourceNotFoundError("User not found")

    def update_user_properties(self, username, realm, **kwargs):
        """
        Update user properties
        """
        headers = self.__get_admin_access_token_headers()
        user_object = self.get_user_by_username(username, realm)
        if user_object:
            url = "{0}/admin/realms/{1}/users/{2}".format(
                self.base_url, realm, user_object["id"]
            )
            for key, value in kwargs.items():
                if key in user_object:
                    self.logger.debug("Changing value: {}".format(value))
                    user_object[key] = value
                else:
                    self.logger.warning(
                        "'{0}' not a valid client property. Skipping...".format(key)
                    )
            self.send_request("put", url, data=json.dumps(user_object), headers=headers)

            updated_user = self.get_user_by_username(username)
            self.logger.info("User '{0}' updated: {1}".format(username, updated_user))
            return updated_user
        else:
            self.logger.info(
                "Cannot update user '{0}' properties. User not found".format(username)
            )
            return

    # TBM: methods that call this usually have a `realm` parameter, but here the
    # realm is hardcoded.
    def get_user_id_and_credentials(self, username):
        """
        Gets user ID and credentials
        username: user's username in Keycloak
        """
        headers = self.__get_admin_access_token_headers()
        user = self.get_user_by_username(username, self.mfa_realm)
        url = "{0}/admin/realms/{1}/users/{2}/credentials".format(
            self.base_url, self.mfa_realm, user["id"]
        )
        ret = self.send_request("get", url, headers=headers)
        self.logger.info("Getting credentials for user '{0}'".format(username))
        credentials = json.loads(ret.text)
        return user["id"], credentials

    def get_user_and_mfa_credentials(self, username):
        """
        Gets user and credentials
        username: user's username in Keycloak
        """
        headers = self.__get_admin_access_token_headers()
        user = self.get_user_by_username(username, self.mfa_realm)
        url = "{0}/admin/realms/{1}/users/{2}/credentials".format(
            self.base_url, self.mfa_realm, user["id"]
        )
        ret = self.send_request("get", url, headers=headers)
        self.logger.info("Getting credentials for user '{0}'".format(username))
        credentials = json.loads(ret.text)
        return user, credentials

    def delete_user_credential_by_id(self, user_id, credential_id):
        """
        Deletes user credential by user_id and credential_id
        user_id: user's UUID in Keylcoak
        credential_id: UUID of the credential
        """
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/users/{2}/credentials/{3}".format(
            self.base_url, self.mfa_realm, user_id, credential_id
        )
        ret = self.send_request("delete", url, headers=headers)
        self.logger.info(
            "Deleted credential with ID {0} from user {1}".format(
                credential_id, user_id
            )
        )
        return ret

    def delete_user_credential_by_type(self, username, credential_type):
        """
        Deletes user credential by credential type
        username: users's username in Keycloak
        credential_type: string that matches the 'type' attribute, e.g. "otp"
        """
        user_id, credentials = self.get_user_id_and_credentials(username)
        for credential in credentials:
            if credential["type"] == credential_type:
                self.delete_user_credential_by_id(user_id, credential["id"])
        return

    def delete_user_required_action_if_exists(self, username, required_action):
        """
        Deletes user required action if the required action exists
        username: users's username in Keycloak
        required_action: string that matches the action type, e.g. "CONFIGURE_TOTP"
        """
        user = self.get_user_by_username(username, self.mfa_realm)
        required_actions = user["requiredActions"]
        try:
            required_actions.remove(required_action)
        except Exception:
            logging.error("Exception caught trying to remove user['requiredActions']")
        self.update_user_properties(
            username, self.mfa_realm, requiredActions=required_actions
        )

    def create_user(self, username, realm=None):
        """
        Creates a new user resource on the server
        https://www.keycloak.org/docs-api/10.0/rest-api/index.html#_users_resource
        """
        if not realm:
            realm = self.realm
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/users".format(
            self.base_url, realm
        )

        user_data = {"username": username}
        ret = self.send_request("post", url, data=json.dumps(user_data), headers=headers)
        return ret

    def delete_user(self, user_id, realm=None):
        """
        Deletes a user resource on the server
        https://www.keycloak.org/docs-api/10.0/rest-api/index.html#_users_resource
        """
        if not realm:
            realm = self.realm
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/users/{2}".format(
            self.base_url, realm, user_id
        )

        ret = self.send_request("delete", url, headers=headers)
        return ret

    def enable_otp_for_user(self, username):
        """
        Sets up a required action to configure OTP for a user
        username: users's username in Keycloak
        """
        user = self.get_user_by_username(username, self.mfa_realm)
        required_actions = user["requiredActions"]
        required_actions.append(self.REQUIRED_ACTION_CONFIGURE_OTP)
        self.update_user_properties(
            username, self.mfa_realm, requiredActions=required_actions
        )

    def enable_webauthn_for_user(self, username):
        """
        Sets up a required action to configure WebAuthn for a user
        username: users's username in Keycloak
        """
        user = self.get_user_by_username(username, self.mfa_realm)
        required_actions = user["requiredActions"]
        required_actions.append(self.REQUIRED_ACTION_WEBAUTHN_REGISTER)
        self.update_user_properties(
            username, self.mfa_realm, requiredActions=required_actions
        )

    def disable_otp_for_user(self, username):
        """
        Deletes all OTP-related credentials and required actions
        username: users's username in Keycloak
        """
        self.delete_user_credential_by_type(username, self.CREDENTIAL_TYPE_OTP)
        self.delete_user_required_action_if_exists(
            username, self.REQUIRED_ACTION_CONFIGURE_OTP
        )

    def disable_webauthn_for_user(self, username):
        """
        Deletes all WebAuthn related credentials and required actions
        username: users's username in Keycloak
        """
        self.delete_user_credential_by_type(username, self.CREDENTIAL_TYPE_WEBAUTHN)
        self.delete_user_required_action_if_exists(
            username, self.REQUIRED_ACTION_WEBAUTHN_REGISTER
        )

    def is_credential_enabled_for_user(
        self, username, required_action_type, credential_type
    ):
        """
        Returns True if the required action type or credential type is present for a user, False otherwise
        username: users's username in Keycloak
        required_action_type: string that matches the action type, e.g. "CONFIGURE_TOTP"
        credential_type: string that matches the 'type' attribute, e.g. "otp"
        :return: Boolean
        """
        user = self.get_user_by_username(username, self.mfa_realm)
        required_actions = user["requiredActions"]
        if required_action_type in required_actions:
            return True
        _, credentials = self.get_user_id_and_credentials(username)
        for credential in credentials:
            if credential["type"] == credential_type:
                return True
        return False

    def _has_credential(self, credentials, credential_type):
        for credential in credentials:
            if credential["type"] == credential_type:
                return True
        return False

    def get_user_mfa_settings(self, username):
        user, credentials = self.get_user_and_mfa_credentials(username)
        otp_must_initialize = (
            self.REQUIRED_ACTION_CONFIGURE_OTP in user["requiredActions"]
        )
        otp_enabled = otp_must_initialize or self._has_credential(
            credentials, self.CREDENTIAL_TYPE_OTP
        )
        webauthn_must_initialize = (
            self.REQUIRED_ACTION_WEBAUTHN_REGISTER in user["requiredActions"]
        )
        webauthn_enabled = webauthn_must_initialize or self._has_credential(
            credentials, self.CREDENTIAL_TYPE_WEBAUTHN
        )
        return (
            otp_enabled,
            otp_must_initialize,
            webauthn_enabled,
            webauthn_must_initialize,
        )


keycloak_client: KeycloakAPIClient = KeycloakAPIClient()
