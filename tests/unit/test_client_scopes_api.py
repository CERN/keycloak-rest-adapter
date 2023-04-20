import unittest
import json
from unittest.mock import MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestScopes(WebTestBase):
    """
    Test the scopes API
    """

    def _get_endpoint(self):
        return f"{API_ROOT}/client/scopes"

    def test_get_scopes_ok(self):
        # prepare
        mock_response = [
            {
                "id": "ae5f650d-430b-4ab5-a7ea-a478bfa95f8f",
                "name": "address",
                "description": "OpenID Connect built-in scope: address",
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "true",
                    "consent.screen.text": "${addressScopeConsentText}"
                },
                "protocolMappers": [
                    {
                        "id": "8edc78fe-0b96-467f-acb9-8b846a237504",
                        "name": "address",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-address-mapper",
                        "consentRequired": False,
                        "config": {
                            "user.attribute.formatted": "formatted",
                            "user.attribute.country": "country",
                            "user.attribute.postal_code": "postal_code",
                            "userinfo.token.claim": "true",
                            "user.attribute.street": "street",
                            "id.token.claim": "true",
                            "user.attribute.region": "region",
                            "access.token.claim": "true",
                            "user.attribute.locality": "locality"
                        }
                    }
                ]
            }]
        self.keycloak_api_mock.get_scopes.return_value = mock_response

        # act
        resp = self.app_client.get(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertListEqual(mock_response, resp.json)


class TestDefaultClientScopes(WebTestBase):
    client_id = "target"

    def _get_endpoint(self):
        return f"{API_ROOT}/client/{self.client_id}/default-scopes"

    mock_good_response = [
        {
            "id": "bea143fe-6db2-460e-9037-b40299106b0d",
            "name": "saml-cern-login-info"
        },
        {
            "id": "b51af49f-a734-4ec8-a4ba-f829a5a39083",
            "name": "saml-roles"
        },
        {
            "id": "eb89ced7-38e2-4c8e-8e59-91612f852ec6",
            "name": "saml-cern-profile"
        }]

    def test_get_default_scopes_ok(self):
        # prepare
        self.keycloak_api_mock.get_client_default_scopes.return_value = self.mock_good_response

        # act
        resp = self.app_client.get(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertListEqual(self.mock_good_response, resp.json)

    def test_get_default_scopes_invalid_client(self):
        # prepare
        self.keycloak_api_mock.get_client_default_scopes.return_value = None

        # act
        resp = self.app_client.get(self._get_endpoint())

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("data" in resp.json)
        self.assertTrue("Check if client exists".casefold() in resp.json["data"].casefold())


class TestManageDefaultClientScopes(WebTestBase):
    client_id = "target"
    scope_id = "1234-asdbc-1234-asdsdf"

    def _get_endpoint(self):
        return f"{API_ROOT}/client/{self.client_id}/default-scopes/{self.scope_id}"

    def test_add_scope_ok(self):
        # prepare
        self.keycloak_api_mock.add_client_scope.return_value = {"ok": True}
        # act
        resp = self.app_client.put(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("successfully".casefold() in resp.json["data"].casefold())

    def test_delete_scope_ok(self):
        # prepare
        self.keycloak_api_mock.delete_client_scope.return_value = {"ok": True}
        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("successfully".casefold() in resp.json["data"].casefold())

    def test_add_invalid_client(self):
        # prepare
        self.keycloak_api_mock.add_client_scope.return_value = None

        # act
        resp = self.app_client.put(self._get_endpoint())

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("Check if client and scope exist".casefold() in resp.json["data"].casefold())

    def test_delete_invalid_client(self):
        # prepare
        self.keycloak_api_mock.delete_client_scope.return_value = None

        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("Check if client and scope exist".casefold() in resp.json["data"].casefold())
