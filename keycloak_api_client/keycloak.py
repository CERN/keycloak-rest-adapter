#!/usr/bin/env python

import json
import logging
import requests
import ssl
import sys
from pprint import pprint

class KeycloakAPIClient(object):

    # To be investigated:
    # https://stackoverflow.com/questions/46470477/how-to-get-keycloak-users-via-rest-without-admin-account

    """
    KeycloakAPI Client to interact with the Keycloak API.
    """

    def __init__(
        self,
        server,
        realm,
        admin_user,
        admin_password,
        client_id,
        client_secret,
        master_realm="master",
    ):
        """
        Initialize the class with the params needed to use the API.
        config_file: Path to file  with config to instanciate the Keycloak Client
        """
        self.keycloak_server = server
        self.realm = realm
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.client_id = client_id
        self.client_secret = client_secret
        self.master_realm = master_realm

        self.base_url = "{}/auth".format(self.keycloak_server)
        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.logger = self.__configure_logging()

        # Persistent SSL configuration
        # http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        self.session = requests.Session()
        self.logger.info(
            "Client configured to talk to '{0}' server and realm '{1}'".format(
                self.keycloak_server, self.realm
            )
        )
        self.access_token_object = None
        self.master_realm_client = self.get_client_by_clientID("master-realm", self.master_realm)

    def __configure_logging(self):
        """Logging setup
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s")

        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        logger.addHandler(console)

        # Requests logs some stuff at INFO that we don't want
        # unless we have DEBUG
        requests_log = logging.getLogger("requests")
        requests_log.setLevel(logging.ERROR)
        return logger

    def __send_request(self, request_type, url, **kwargs):
        # if there is 'headers' in kwargs use it instead of default class one
        r_headers = self.headers.copy()
        kwargs['verify'] = False
        if "headers" in kwargs:
            r_headers.update(kwargs.pop("headers", None))

        if request_type.lower() == "delete":
            ret = self.session.delete(url=url, headers=r_headers, **kwargs)
        elif request_type.lower() == "get":
            ret = self.session.get(url=url, headers=r_headers, **kwargs)
        elif request_type.lower() == "post":
            ret = self.session.post(url=url, headers=r_headers, **kwargs)
        elif request_type.lower() == "put":
            ret = self.session.put(url=url, headers=r_headers, **kwargs)
        else:
            raise Exception("Specified request_type '{0}' not supported".format(request_type))
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

        if self.access_token_object == None:
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
            "Setting client '{0}' fine grain permissions to '{1}'".format(clientid, status))
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
        self.logger.info("Creating mapper with the following configuration: {0}".format(kwargs))
        client_object = self.get_client_by_clientID(client_id)
        if client_object:
            url = '{0}/admin/realms/{1}/clients/{2}/protocol-mappers/models'.format(
            self.base_url, self.realm, client_object['id'])
            ret = self.send_request(
                    'post',
                     url,
                     data=json.dumps(kwargs),
                     headers=headers)
            return ret
        else:
            self.logger.info("Cannot update client '{0}' mappers. Client not found".format(client_id))
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
        self.logger.info("Updating mapper with the following configuration: {0}".format(kwargs))
        client_object = self.get_client_by_clientID(client_id)
        if client_object:
            if 'protocolMappers' in client_object:
                for mapper in client_object['protocolMappers']:
                    if mapper['name'] == mapper_name:
                        url = '{0}/admin/realms/{1}/clients/{2}/protocol-mappers/models/{3}'.format(
                        self.base_url, self.realm, client_object['id'], mapper['id'])
                        updated_mapper = mapper
                        for key in kwargs.iterkeys():
                            if mapper['config'].has_key(key):
                                updated_mapper['config'][key] = kwargs[key]
                            else:
                                self.logger.error("'{0}' not a valid mapper attribute. Mapper not updated".format(key))
                                return # not update and return empty

                        ret = self.send_request(
                                'put',
                                url,
                                data=json.dumps(updated_mapper),
                                headers=headers)
                        return ret

                self.logger.info("Cannot mapper '{0}' for client '{1}'. Protocol mapper not found".format(mapper_name, client_id))
                return

            else:
                self.logger.info("Cannot update client '{0}' mapper. Client mappers not found".format(client_id))
                return
        else:
            self.logger.info("Cannot update client '{0}' mappers. Client not found".format(client_id))
            return

    def update_client_properties(self, client_id, **kwargs):
        """
        Update existing client properties
        kwargs: { "property_name": "new_value", ... , }
        Returns: Updated client object
        """
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_clientID(client_id)
        self.logger.info(
            "Updating client with the following new propeties: {0}".format(kwargs)
        )
        if client_object:
            url = "{0}/admin/realms/{1}/clients/{2}".format(
                self.base_url, self.realm, client_object["id"]
            )
            for key, value in kwargs.items():
                if key in client_object:
                    self.logger.debug("Changing value: {}".format(value))
                    client_object[key] = value
                else:
                    self.logger.warn(
                        "'{0}' not a valid client property. Skipping...".format(
                            key
                        )
                    )

            ret = self.send_request(
                "put", url, data=json.dumps(client_object), headers=headers
            )

            updated_client = self.get_client_by_clientID(client_id)
            self.logger.info(
                "Client '{0}' updated: {1}".format(client_id, updated_client)
            )
            return updated_client
        else:
            self.logger.info("Cannot update client '{0}' properties. Client not found".format(client_id))
            return

    def client_description_converter(self, payload):
        """
        Create a new client via its client description (xml or json)
        payload: XML or JSON definition of the client
        Returns: New client object
        """
        self.logger.info("Attempting to create new client via description converter...")
        headers = self.__get_admin_access_token_headers()

        url = "{0}/admin/realms/{1}/client-description-converter".format(
            self.base_url, self.realm
        )
        ret = self.send_request("post", url, headers=headers, data=payload)
        access_token = headers["Authorization"].split()[1]
        return self.__create_client(access_token, **json.loads(ret.text))

    def regenerate_client_secret(self, client_id):
        """
        Regenerate client secret of the given client
        """
        self.logger.info("Attempting to regenerate '{0}' secret...".format(client_id))
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_clientID(client_id)
        if client_object:
            if client_object['protocol'] == 'openid-connect':
                url = '{0}/admin/realms/{1}/clients/{2}/client-secret'.format(
                     self.base_url, self.realm, client_object['id'])

                ret = self.send_request(
                    'post',
                    url,
                    headers=headers)
                self.logger.info("Client '{0}' secret regenerated".format(client_id))
            else:
                ret = requests.Response  # new empty response
                ret.text = "Cannot regenerate client '{0}' secret. Client not openid type".format(
                    client_id
                )
                self.logger.info(ret.text)
            return ret
        else:
            self.logger.info("Cannot regenerate client '{0}' secret. Client not found".format(client_id))

    def delete_client_by_clientID(self, client_id):
        """
        Delete client with the given clientID name
        """
        headers = self.__get_admin_access_token_headers()
        client_object = self.get_client_by_clientID(client_id)
        if client_object:
            url = "{0}/admin/realms/{1}/clients/{2}".format(
                self.base_url, self.realm, client_object["id"]
            )

            ret = self.send_request(
                'delete',
                url,
                headers=headers)
            self.logger.info("Deleted client '{0}'".format(client_id))
            return ret
        else:
            self.logger.info("Cannot delete '{0}'. Client not found".format(client_id))

    def get_client_by_clientID(self, client_id, realm=None):
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
            self.logger.info("Found client '{0}' ({1})".format(client_id, client[0]['id']))
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
        self.logger.info("Creating policy new '{0}' for client {1}".format(policy_name, clientid))
        headers = self.__get_admin_access_token_headers()
        url = "{0}/admin/realms/{1}/clients/{2}/authz/resource-server/policy/client".format(
            self.base_url, self.realm, self.master_realm_client["id"]
        )

        self.logger.info("Checking if '{0}' already exists...".format(policy_name))
        client_policy = self.get_client_policy_by_name(policy_name)

        if len(client_policy) == 0:
            # create new policy
            self.logger.info(
                "It does not exist. Creating new policy and subscribing it to client '{0}'".format(clientid))
            http_method = 'post'
            subscribed_clients = [clientid]

        else:
            # update already existing policy
            self.logger.info(
                "There is an exisintg policy with name {0}. Updating it to subscribe client '{1}'".format(policy_name, clientid))
            url = url + "/{0}".format(client_policy[0]['id'])
            http_method = 'put'
            subscribed_clients = json.loads(
                client_policy[0]['config']['clients'])
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
        self.logger.info("Getting authorization permission '{0}' object".format(
                    permission_name))
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
            "Getting token-exhange permission for client '{0}'...".format(clientid))
        token_exchange_permission_name = "token-exchange.permission.client.{0}".format(
            clientid
        )
        return self.get_auth_permission_by_name(token_exchange_permission_name)[0]

    def grant_token_exchange_permissions(self, target_clientid, requestor_clientid):
        """
        Grant token-exchange permission for target client to destination client
        target_clientid: ID string of the target client. E.g: 6781736b-e1f7-4ff7-a883-f4168c4dbd8a
        requestor_clientid: ID string of the client to exchange its token for target_clientid E.g: 6781736b-e1f7-4ff7-a883-f4168c4dbd8a
        """
        self.set_client_fine_grain_permission(target_clientid, True)
        client_token_exchange_permission = self.get_client_token_exchange_permission(
            target_clientid
        )
        tep_associated_policies = self.get_permission_associated_policies(
            client_token_exchange_permission["id"]
        )
        policies = [policy["id"] for policy in tep_associated_policies]

        policy_name = "allow token exchange for {0}".format(requestor_clientid)
        policy_description = "Allow token exchange for '{0}' client".format(
            requestor_clientid
        )

        self.create_client_policy(requestor_clientid, policy_name, policy_description)
        policy = self.get_client_policy_by_name(policy_name)[0]

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

        client_token_exchange_permission['policies'] = policies
        client_token_exchange_permission['policies'].append(policy['id'])
        self.logger.info("Granting token-exhange between client '{0}' and '{1}'".format(
                    target_clientid, requestor_clientid))
        ret = self.send_request(
            "put",
            url,
            headers=headers,
            data=json.dumps(client_token_exchange_permission),
        )
        return ret

    def get_permission_associated_policies(self, permission_id):
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

    def refresh_admin_token(self, admin_token):
        """
        https://www.keycloak.org/docs/2.5/server_development/topics/admin-rest-api.html
        """
        self.logger.info("Refreshing admin access token")
        grant_type = "refresh_token"
        refresh_token = access_token_object["refresh_token"]

        url = "{0}/realms/{1}/protocol/openid-connect/token".format(
            self.base_url, self.realm
        )
        payload = "refresh_token={0}&grant_type={1}&username={2}&password={3}".format(
            refresh_token, grant_type, self.admin_user, self.admin_password
        )
        ret = self.send_request("post", url, data=payload)
        return json.loads(ret.tex)

    def get_admin_access_token(self):
        """
        https://www.keycloak.org/docs/2.5/server_development/topics/admin-rest-api.html
        """
        self.logger.info("Getting admin access token")

        client_id = "admin-cli"
        grant_type = "password"

        url = "{0}/realms/{1}/protocol/openid-connect/token".format(
            self.base_url, self.master_realm
        )
        payload = "client_id={0}&grant_type={1}&username={2}&password={3}".format(
            client_id, grant_type, self.admin_user, self.admin_password
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
            self.base_url, self.realm
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
            "Authorization": "{0}".format(access_token),
        }
        url = "{0}/realms/{1}/clients-registrations/default".format(
            self.base_url, self.realm
        )
        self.logger.info(
            "Creating client '{0}' --> {1}".format(kwargs["clientId"], kwargs)
        )
        return self.send_request("post", url, headers=headers, data=json.dumps(kwargs))

    def logout_user(self, user_id):
        """
        Logs out the user from all his sessions
        """
        access_token = self.get_access_token()
        url = '{0}/admin/realms/{1}/users/{2}/logout'.format(
            self.base_url, self.realm, user_id
        )
        self.logger.info("Logging out user ID '{0}'".format(user_id))
        return self.send_request('post', url)

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
            json_response = response.json()
            update_response = self.update_client_properties(json_response["clientId"], **kwargs)
            update_response["secret"] = json_response["secret"]
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
        return self.__create_client(access_token, **kwargs).json()

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
        url = "{0}/admin/realms/{1}/users?first=0&max=1&search={2}".format(self.base_url, realm, username)

        ret = self.send_request("get", url, headers=headers)

        self.logger.info("Getting user '{0}' object".format(username))
        user = json.loads(ret.text)

        # keycloak returns a list of 1 element if found, empty if not
        if len(user) == 1 and user[0]['username'] == username:
            self.logger.info("Found user '{0}' ({1})".format(username, user[0]['id']))
            return user[0]
        else:
            self.logger.info("User '{0}' NOT found".format(username))
            return None

    def update_user_properties(self, username, **kwargs):
        """
        Update user properties
        """
        headers = self.__get_admin_access_token_headers()
        user_object = self.get_user_by_username(username)
        if user_object:
            url = "{0}/admin/realms/{1}/users/{2}".format(
                self.base_url, self.realm, user_object["id"]
            )
            for key, value in kwargs.items():
                if key in user_object:
                    self.logger.debug("Changing value: {}".format(value))
                    user_object[key] = value
                else:
                    self.logger.warn(
                        "'{0}' not a valid client property. Skipping...".format(
                            key
                        )
                    )
            self.send_request(
                "put", url, data=json.dumps(user_object), headers=headers
            )

            updated_user = self.get_user_by_username(username)
            self.logger.info(
                "User '{0}' updated: {1}".format(username, updated_user)
            )
            return updated_user
        else:
            self.logger.info("Cannot update user '{0}' properties. User not found".format(username))
            return
