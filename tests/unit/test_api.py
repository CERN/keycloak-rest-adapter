import json
import os
import requests
import sys
import unittest
import sys, os

from configparser import ConfigParser


pathname = os.path.dirname(sys.argv[0])
config_dir = os.path.abspath(pathname)
config_file = "{0}/keycloak_client.cfg".format(config_dir)
session = requests.Session()


def __send_request(request_type, url, **kwargs):
    if request_type.lower() == "delete":
        ret = session.delete(url=url, **kwargs)
    elif request_type.lower() == "get":
        ret = session.get(url=url, **kwargs)
    elif request_type.lower() == "post":
        ret = session.post(url=url, **kwargs)
    elif request_type.lower() == "put":
        ret = session.put(url=url, **kwargs)
    else:
        raise Exception("Specified request_type '%s' not supported" % request_type)
    return ret


def send_request(request_type, url, **kwargs):
    """ Call the private method __send_request and retry in case the access_token has expired"""
    try:
        ret = __send_request(request_type, url, **kwargs)
    except requests.exceptions.ConnectionError as e:
        msg = "Cannot process the request. Is the keycloak server down?"
        raise Exception(msg)
    return ret


def get_admin_access_token(keycloak_server, realm, admin_user, admin_password):
    """
    https://www.keycloak.org/docs/2.5/server_development/topics/admin-rest-api.html
    """
    client_id = "admin-cli"
    grant_type = "password"

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    url = "https://{0}/auth/realms/{1}/protocol/openid-connect/token".format(
        keycloak_server, realm
    )
    payload = "client_id={0}&grant_type={1}&username={2}&password={3}".format(
        client_id, grant_type, admin_user, admin_password
    )
    ret = send_request("post", url, headers=headers, data=payload)
    return json.loads(ret.text)


def get_admin_access_token_headers(keycloak_server, realm, admin_user, admin_password):
    """
    Get HTTP headers with an admin bearer token
    """
    access_token_object = get_admin_access_token(
        keycloak_server, realm, admin_user, admin_password
    )
    access_token = access_token_object["access_token"]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer {0}".format(access_token),
    }
    return headers


class TestKeycloakClient(unittest.TestCase):
    def setUp(self):

        config = ConfigParser()
        config.readfp(open(config_file))

        keycloak_server = config.get("keycloak", "server")
        adapter_server = config.get("keycloak", "adapter")
        realm = config.get("keycloak", "realm")
        admin_user = config.get("keycloak", "admin_user")
        admin_password = config.get("keycloak", "admin_password")
        ssl_cert_path = config.get("keycloak", "ssl_cert_path")
        session.verify = ssl_cert_path

        self.baseurl = "https://{0}/api/v1.0".format(adapter_server)
        self.clientId = "AAAAAAmadeonthespot-danielfr"

        self.headers = get_admin_access_token_headers(
            keycloak_server, realm, admin_user, admin_password
        )
        send_request(
            "delete",
            "{0}/client/{1}".format(self.baseurl, self.clientId),
            headers=self.headers,
        ).text

    def test_01_create_saml_client_return_created_client(self):
        data = {}
        data["clientId"] = self.clientId
        url = "{0}/client/saml".format(self.baseurl)
        new_client = send_request("post", url, headers=self.headers, data=data).text
        self.assertEqual(json.loads(new_client)["clientId"], self.clientId)
        # annnd delete client
        send_request(
            "delete",
            "{0}/client/{1}".format(self.baseurl, self.clientId),
            headers=self.headers,
        ).text

    def test_03_delete_client_return_not_found(self):
        non_exisiting_client = "non_exisiting_client"
        url = "{0}/client/{1}".format(self.baseurl, non_exisiting_client)
        response = send_request("delete", url, headers=self.headers).text
        self.assertEqual(
            response,
            "Cannot delete client '{0}'. Client not found".format(non_exisiting_client),
        )

    def test_04_create_saml_client_with_protocol_return_created_client(self):
        data = {}
        protocol = "saml"
        data["clientId"] = self.clientId
        data["protocol"] = protocol
        url = "{0}/client".format(self.baseurl)
        new_client = (send_request("post", url, headers=self.headers, data=data)).text
        self.assertEqual(json.loads(new_client)["clientId"], self.clientId)
        # annnd delete client
        send_request(
            "delete", "{0}/client/{1}/{2}".format(self.baseurl, protocol, self.clientId)
        ).text

    def test_05_create_openid_client_with_protocol_return_created_client(self):
        data = {}
        protocol = "openid"
        data["clientId"] = self.clientId
        data["protocol"] = protocol
        url = "{0}/client".format(self.baseurl)
        new_client = (send_request("post", url, headers=self.headers, data=data)).text
        self.assertEqual(json.loads(new_client)["clientId"], self.clientId)
        # annnd delete client
        send_request(
            "delete",
            "{0}/client/{1}/{2}".format(self.baseurl, protocol, self.clientId),
            headers=self.headers,
        ).text

    def test_06_create_openid_client_return_created_client(self):
        data = {}
        data["clientId"] = self.clientId
        url = "{0}/client/openid".format(self.baseurl)
        new_client = (send_request("post", url, headers=self.headers, data=data)).text
        self.assertEqual(json.loads(new_client)["clientId"], self.clientId)
        # annnd delete client
        send_request(
            "delete",
            "{0}/client/{1}".format(self.baseurl, self.clientId),
            headers=self.headers,
        ).text

    def test_07_regerentate_client_secret_changes_secret(self):
        data = {}
        data["clientId"] = self.clientId
        url = "{0}/client/openid".format(self.baseurl)
        new_client = (send_request("post", url, headers=self.headers, data=data)).text
        secret = json.loads(new_client)["secret"]
        new_secret = send_request(
            "post",
            "{0}/client/openid/{1}/regenerate-secret".format(
                self.baseurl, self.clientId
            ),
            headers=self.headers,
        ).text
        self.assertNotEqual(json.loads(new_secret)["value"], secret)
        # annnd delete client
        send_request(
            "delete",
            "{0}/client/{1}".format(self.baseurl, self.clientId),
            headers=self.headers,
        ).text

    def test_08_client_update_changes_property(self):
        data = {}
        data["clientId"] = self.clientId
        data["description"] = "Old description"
        url = "{0}/client/openid".format(self.baseurl)
        new_client = (send_request("post", url, headers=self.headers, data=data)).text
        data = {}
        data["description"] = "New description"
        url = "{0}/client/{1}".format(self.baseurl, self.clientId)
        updated_client = (requests.put(url, headers=self.headers, data=data)).text
        self.assertEqual(json.loads(updated_client)["description"], "New description")
        # annnd delete client
        send_request(
            "delete",
            "{0}/client/{1}".format(self.baseurl, self.clientId),
            headers=self.headers,
        ).text


def main():
    unittest.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        sys.exit(1)
