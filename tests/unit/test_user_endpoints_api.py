import unittest
import json
from unittest.mock import MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestUserEndpointsApi(WebTestBase):
    """
    Test the user endpoints (logout / update props)
    """

    user_id = "cristi"

    def _get_logout_endpoint(self):
        return f"{API_ROOT}/user/logout/{self.user_id}"

    def _get_update_endpoint(self):
        return f"{API_ROOT}/user/{self.user_id}"

    def test_logout_user_id_valid_response(self):
        # prepare
        self.keycloak_api_mock.logout_user.return_value.text = "success"

        # act
        resp = self.app_client.delete(self._get_logout_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertEqual("success", resp.json["data"])
        self.keycloak_api_mock.logout_user.assert_called_with(self.user_id)

    def test_update_user_valid_response(self):
        # prepare
        response_mock = {"username": self.user_id}
        body = {"username": self.user_id, "age": 42}
        self.keycloak_api_mock.update_user_properties.return_value = response_mock
        self.keycloak_api_mock.realm = "cern"

        # act
        resp = self.app_client.put(self._get_update_endpoint(),
            data=json.dumps(body),
            content_type='application/json')

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertEqual(response_mock, resp.json)
        self.keycloak_api_mock.update_user_properties.assert_called_with(self.user_id, "cern", **body)

    def test_update_user_invalid_response(self):
        # prepare
        body = {"username": self.user_id, "age": 42}
        self.keycloak_api_mock.update_user_properties.return_value = None
        self.keycloak_api_mock.realm = "cern"

        # act
        resp = self.app_client.put(self._get_update_endpoint(),
            data=json.dumps(body),
            content_type='application/json')

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue(f"Cannot update '{self.user_id}'".casefold() in resp.json["data"].casefold())
        self.keycloak_api_mock.update_user_properties.assert_called_with(self.user_id, "cern", **body)
