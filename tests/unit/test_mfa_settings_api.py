import json
import unittest
from unittest.mock import MagicMock, call, patch

from tests.utils.tools import (
    API_ROOT,
    CREDENTIAL_TYPE_OTP,
    CREDENTIAL_TYPE_WEBAUTHN,
    REQUIRED_ACTION_CONFIGURE_OTP,
    REQUIRED_ACTION_WEBAUTHN_REGISTER,
    WebTestBase,
)
from utils import ResourceNotFoundError


class TestUserEndpointsApi(WebTestBase):
    """
    Test the user endpoints (logout / update props)
    """

    user_id = "cristi"

    def _get_mfa_settings_endpoint(self):
        return f"{API_ROOT}/user/{self.user_id}/authenticator"

    def _get_otp_endpoint(self):
        return f"{self._get_mfa_settings_endpoint()}/otp"

    def _get_webauthn_endpoint(self):
        return f"{self._get_mfa_settings_endpoint()}/webauthn"

    def _get_webauthn_reset_endpoint(self):
        return f"{self._get_webauthn_endpoint()}/reset"

    def _get_otp_reset_endpoint(self):
        return f"{self._get_otp_endpoint()}/reset"

    def _mock_user_auth(self, multifactor=False):
        """
        Mocks the auth to simulate a user accessing his credentials
        """
        resource_access = self.user_info_mock()["resource_access"]
        roles = ["user"]
        if multifactor:
            roles = ["user_mfa"]
        resource_access["keycloak-rest-adapter"]["roles"] = roles
        self.user_info_mock.return_value = {
            "sub": self.user_id,
            "resource_access": resource_access,
        }

    def _mock_user_auth_no_sub(self):
        """
        Mocks the auth to simulate a user accessing his credentials without any "sub" claim
        """
        resource_access = self.user_info_mock()["resource_access"]
        resource_access["keycloak-rest-adapter"]["roles"] = ["user"]
        self.user_info_mock.return_value = {"resource_access": resource_access}

    def _mock_user_auth_no_role(self):
        """
        Mocks the auth with no roles claims
        """
        self.user_info_mock.return_value = {"test": "value"}

    def test_get_mfa_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.get_user_mfa_settings.side_effect = ResourceNotFoundError(
            "not found"
        )
        # act
        resp = self.app_client.get(self._get_mfa_settings_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_get_mfa_settings_not_found_user_access(self):
        # prepare
        self._mock_user_auth()
        self.keycloak_api_mock.get_user_mfa_settings.side_effect = ResourceNotFoundError(
            "not found"
        )
        # act
        resp = self.app_client.get(self._get_mfa_settings_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_get_mfa_settings_ok(self):
        # prepare
        self.keycloak_api_mock.get_user_mfa_settings.return_value = (
            True,  # enabled (OTP)
            True,  # preferred (OTP)
            "08d8429j-0c2e-486a-8n97-084e7ec7we7d",  # credential_id (OTP)
            False,  # initialization_required (OTP)
            False,  # enabled (WenAuthn)
            False,  # preferred (WenAuthn)
            None,  # credential_id (WenAuthn)
            True,  # initialization_required (WenAuthn)
        )

        # act
        resp = self.app_client.get(self._get_mfa_settings_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.json["data"]["otp"]["enabled"])
        self.assertTrue(resp.json["data"]["otp"]["preferred"])
        self.assertEqual(
            "08d8429j-0c2e-486a-8n97-084e7ec7we7d",
            resp.json["data"]["otp"]["credential_id"],
        )
        self.assertFalse(resp.json["data"]["otp"]["initialization_required"])
        self.assertFalse(resp.json["data"]["webauthn"]["enabled"])
        self.assertFalse(resp.json["data"]["webauthn"]["preferred"])
        self.assertTrue(resp.json["data"]["webauthn"]["initialization_required"])

    # OTP Settings tests
    def test_get_otp_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.get(self._get_otp_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_get_otp_settings_ok(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True

        # act
        resp = self.app_client.get(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual({"enabled": True}, resp.json["data"])
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_post_otp_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_post_otp_settings_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = False

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp enabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_post_otp_settings_not_enabled_user_mfa_auth(self):
        # prepare
        self._mock_user_auth(True)
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = False

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp enabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_post_otp_settings_bad_creds(self):
        # prepare
        self._mock_user_auth_no_sub()

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(401, resp.status_code)

    def test_post_otp_settings_bad_user_roles(self):
        # prepare
        self._mock_user_auth_no_role()

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(401, resp.status_code)

    def test_post_otp_settings_credentials_exception(self):
        # prepare
        self.app_client.environ_base["HTTP_AUTHORIZATION"] = ""

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(401, resp.status_code)

    def test_post_otp_settings_already_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True

        # act
        resp = self.app_client.post(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp already enabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_delete_otp_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.delete(self._get_otp_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_delete_otp_settings_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [
            False,
            False,
        ]

        # act
        resp = self.app_client.delete(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp already disabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_delete_otp_settings_already_enabled_no_webauthn(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [
            True,
            False,
        ]

        # act
        resp = self.app_client.delete(self._get_otp_endpoint())

        # assert
        self.assertEqual(403, resp.status_code)
        self.assertTrue(
            "Cannot disable OTP if WebAuthn is not enabled".casefold()
            in resp.json.casefold()
        )
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_delete_otp_settings_already_enabled_and_webauthn_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [True, True]

        # act
        resp = self.app_client.delete(self._get_otp_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("OTP Disabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_reset_otp_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )
        # act
        resp = self.app_client.post(self._get_otp_reset_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_reset_otp_is_enabled_needs_reset(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True
        # act
        resp = self.app_client.post(self._get_otp_reset_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp Enabled and Reset".casefold() in resp.json.casefold())
        self.keycloak_api_mock.disable_otp_for_user.assert_called_with(self.user_id)
        self.keycloak_api_mock.enable_otp_for_user.assert_called_with(self.user_id)
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    def test_reset_otp_is_enabled_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = False
        # act
        resp = self.app_client.post(self._get_otp_reset_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("otp Enabled and Reset".casefold() in resp.json.casefold())
        self.keycloak_api_mock.disable_otp_for_user.assert_not_called()
        self.keycloak_api_mock.enable_otp_for_user.assert_called_with(self.user_id)
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP
        )

    # WebAuthN endpoints

    def test_get_webauthn_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.get(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_get_webauthn_settings_ok(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True

        # act
        resp = self.app_client.get(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual({"enabled": True}, resp.json["data"])
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )

    def test_post_webauthn_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.post(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_post_webauthn_settings_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = False

        # act
        resp = self.app_client.post(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("webauthn enabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )

    def test_post_webauthn_settings_already_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True

        # act
        resp = self.app_client.post(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("webauthn already enabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )

    def test_delete_webauthn_settings_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )

        # act
        resp = self.app_client.delete(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())

    def test_delete_webauthn_settings_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [
            False,
            False,
        ]

        # act
        resp = self.app_client.delete(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("webauthn already disabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_delete_webauthn_settings_already_enabled_no_webauthn(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [
            False,
            True,
        ]

        # act
        resp = self.app_client.delete(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(403, resp.status_code)
        self.assertTrue(
            "Cannot disable webauthn if OTP is not enabled".casefold()
            in resp.json.casefold()
        )
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_delete_webauthn_settings_already_enabled_and_webauthn_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = [True, True]

        # act
        resp = self.app_client.delete(self._get_webauthn_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("webauthn Disabled".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_has_calls(
            [
                call(self.user_id, REQUIRED_ACTION_CONFIGURE_OTP, CREDENTIAL_TYPE_OTP),
                call(
                    self.user_id,
                    REQUIRED_ACTION_WEBAUTHN_REGISTER,
                    CREDENTIAL_TYPE_WEBAUTHN,
                ),
            ]
        )

    def test_reset_webauthn_not_found(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.side_effect = ResourceNotFoundError(
            "not found"
        )
        # act
        resp = self.app_client.post(self._get_webauthn_reset_endpoint())

        # assert
        self.assertEqual(404, resp.status_code)
        self.assertTrue("not found".casefold() in resp.json.casefold())
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )

    def test_reset_webauthn_is_enabled_needs_reset(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = True
        # act
        resp = self.app_client.post(self._get_webauthn_reset_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("WebAuthn Enabled and Reset".casefold() in resp.json.casefold())
        self.keycloak_api_mock.disable_webauthn_for_user.assert_called_with(
            self.user_id
        )
        self.keycloak_api_mock.enable_webauthn_for_user.assert_called_with(self.user_id)
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )

    def test_reset_webauthn_is_enabled_not_enabled(self):
        # prepare
        self.keycloak_api_mock.is_credential_enabled_for_user.return_value = False
        # act
        resp = self.app_client.post(self._get_webauthn_reset_endpoint())

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertTrue("WebAuthn Enabled and Reset".casefold() in resp.json.casefold())
        self.keycloak_api_mock.disable_webauthn_for_user.assert_not_called()
        self.keycloak_api_mock.enable_webauthn_for_user.assert_called_with(self.user_id)
        self.keycloak_api_mock.is_credential_enabled_for_user.assert_called_with(
            self.user_id, REQUIRED_ACTION_WEBAUTHN_REGISTER, CREDENTIAL_TYPE_WEBAUTHN
        )
