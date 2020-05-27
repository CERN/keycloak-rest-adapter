import unittest
from unittest.mock import MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestTokenExchangePermissions(WebTestBase):
    """
    Test cases for the token exchange endpoints
    """

    target_client = "target"
    requestor_client = "requestor"

    def _get_endpoint(self):
        return f"{API_ROOT}/client/openid/{self.target_client}/token-exchange-permissions/{self.requestor_client}"

    def test_delete_token_exchange_missing_client(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            None
        ]

        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)

    def test_delete_token_exchange_bad_response(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            self.requestor_client
        ]
        self.keycloak_api_mock.revoke_token_exchange_permissions.side_effect = ValueError("Clients not found")

        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found" in resp.json.casefold())

    def test_delete_token_exchange_ok(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            self.requestor_client
        ]
        self.keycloak_api_mock.revoke_token_exchange_permissions.return_value.status_code = 200

        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertEqual("deleted", resp.json.casefold())

    def test_delete_token_exchange_problem_removing(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            self.requestor_client
        ]
        self.keycloak_api_mock.revoke_token_exchange_permissions.return_value.status_code = 500
        self.keycloak_api_mock.revoke_token_exchange_permissions.return_value.reason = "error"

        # act
        resp = self.app_client.delete(self._get_endpoint())

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertEqual("error", resp.json.casefold())

    def test_grant_token_exchange_missing_client(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            None
        ]

        # act
        resp = self.app_client.put(self._get_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)

    def test_grant_token_exchange_creation_error(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            self.requestor_client
        ]
        self.keycloak_api_mock.grant_token_exchange_permissions.return_value.status_code = 400
        self.keycloak_api_mock.grant_token_exchange_permissions.return_value.reason = "error"

        # act
        resp = self.app_client.put(self._get_endpoint())

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertEqual("error", resp.json.casefold())
        self.keycloak_api_mock.grant_token_exchange_permissions.assert_called_with(self.target_client, self.requestor_client)

    def test_grant_token_exchange_creation_ok(self):
        # prepare
        self.keycloak_api_mock.get_client_by_client_id.side_effect = [
            self.target_client,
            self.requestor_client
        ]
        self.keycloak_api_mock.grant_token_exchange_permissions.return_value.status_code = 200
        self.keycloak_api_mock.grant_token_exchange_permissions.return_value.reason = "success"

        # act
        resp = self.app_client.put(self._get_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertEqual("success", resp.json.casefold())
        self.keycloak_api_mock.grant_token_exchange_permissions.assert_called_with(self.target_client, self.requestor_client)
