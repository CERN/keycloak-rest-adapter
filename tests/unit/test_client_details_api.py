from model import Client
import unittest
import json
from unittest.mock import ANY, MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestClientDetailsApi(WebTestBase):
    """
    Test the client details endpoints of the API
    """

    client_id = "target"

    def _get_endpoint(self, protocol: str):
        return f"{API_ROOT}/client/{protocol}/{self.client_id}"

    def test_put_openid_client_missing(self):
        # prepare
        self.keycloak_api_mock.update_client_properties.return_value = None
        mock_payload = {"description": "test"}
        # act
        resp = self.app_client.put(
            self._get_endpoint("openid"),
            data=json.dumps(mock_payload),
            content_type="application/json",
        )

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("data" in resp.json)
        self.assertTrue(self.client_id in resp.json["data"].casefold())
        self.keycloak_api_mock.update_client_properties.assert_called_with(
            self.client_id, ANY, client_type="openid"
        )

    def test_put_openid_client_ok(self):
        # prepare
        mock_payload = {"description": "test"}
        mock_response = Client({"clientId": self.client_id, "description": "test"}, app=self.app)
        self.keycloak_api_mock.update_client_properties.return_value = mock_response

        # act
        resp = self.app_client.put(
            self._get_endpoint("openid"),
            data=json.dumps(mock_payload),
            content_type="application/json",
        )
        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual(mock_response.definition, resp.json)
        self.keycloak_api_mock.update_client_properties.assert_called_with(
            self.client_id, ANY, client_type="openid"
        )

    def test_delete_openid_client_bad_protocol(self):
        # act
        resp = self.app_client.delete(self._get_endpoint("testprot"))

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue(
            "The protocol is invalid".casefold() in resp.json["data"].casefold()
        )

    def test_delete_openid_client_missing(self):
        # prepare
        self.keycloak_api_mock.delete_client_by_client_id.return_value = None

        # act
        resp = self.app_client.delete(self._get_endpoint("openid"))

        # assert
        self.assertEqual(404, resp.status_code)
        self.keycloak_api_mock.delete_client_by_client_id.assert_called_with(
            self.client_id
        )

    def test_delete_openid_client_ok(self):
        # prepare
        self.keycloak_api_mock.delete_client_by_client_id.return_value = {"ok": True}

        # act
        resp = self.app_client.delete(self._get_endpoint("openid"))
        # assert
        self.assertEqual(200, resp.status_code)
        self.keycloak_api_mock.delete_client_by_client_id.assert_called_with(
            self.client_id
        )
