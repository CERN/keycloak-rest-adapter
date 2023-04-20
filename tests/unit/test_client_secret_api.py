import unittest
from unittest.mock import MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestClientSecretApi(WebTestBase):
    """
    Test cases for the Flask API client secret sections, mocking the Keycloak connector
    """

    def test_no_credentials(self):
        self.app_client.environ_base["HTTP_AUTHORIZATION"] = ""
        resp = self.app_client.get(f"{API_ROOT}/client/openid/asd/client-secret")
        self.assertEqual(401, resp.status_code)

    def test_valid_credentials_get_client_secret_found(self):
        # setup
        mock_response = {"client_secret": "1234"}
        self.keycloak_api_mock.display_client_secret.return_value.json.return_value = (
            mock_response
        )

        # act
        resp = self.app_client.get(f"{API_ROOT}/client/openid/asd/client-secret")

        # assert
        self.assertEqual(200, resp.status_code, "Response should have been 200")
        self.assertDictEqual(mock_response, resp.json, "Answer was unexpected")

    def test_get_client_secret_not_found(self):
        # setup
        mock_response = None
        self.keycloak_api_mock.display_client_secret.return_value = mock_response

        # act
        resp = self.app_client.get(f"{API_ROOT}/client/openid/asd/client-secret")

        # assert
        self.assertEqual(404, resp.status_code, "Response should have been 404")

    def test_regenerate_client_secret_found(self):
        # setup
        mock_response = {"client_secret": "1234"}
        client_id = "potato-app"
        self.keycloak_api_mock.regenerate_client_secret.return_value.json.return_value = (
            mock_response
        )

        # act
        resp = self.app_client.post(
            f"{API_ROOT}/client/openid/{client_id}/client-secret"
        )

        # assert
        self.keycloak_api_mock.regenerate_client_secret.assert_called_with(client_id)
        self.assertEqual(200, resp.status_code, "Response should have been 200")
        self.assertDictEqual(
            mock_response,
            resp.json,
            "Response should have been the dictionary expected",
        )

    def test_regenerate_client_secret_not_found(self):
        # setup
        mock_response = None
        client_id = "potato-app"
        self.keycloak_api_mock.regenerate_client_secret.return_value = mock_response

        # act
        resp = self.app_client.post(
            f"{API_ROOT}/client/openid/{client_id}/client-secret"
        )

        # assert
        self.assertEqual(404, resp.status_code, "Response should have been 404")
