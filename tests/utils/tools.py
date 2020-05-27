import json
import os
import unittest
from abc import ABCMeta
from unittest.mock import MagicMock, patch

from flask import Flask
from flask.testing import FlaskClient

from app_factory import create_app


def in_ci_job():
    """
    Verify if we're in a CI job or not
    """
    return os.environ.get("CI", False)


def run_integration_tests():
    """
    Verifies whether to run the integration tests or not
    """
    return os.environ.get("RUN_INTEGRATION", False)


API_ROOT = "/api/v1.0"

CREDENTIAL_TYPE_OTP = "otp"
CREDENTIAL_TYPE_WEBAUTHN = "webauthn"
REQUIRED_ACTION_CONFIGURE_OTP = "CONFIGURE_TOTP"
REQUIRED_ACTION_WEBAUTHN_REGISTER = "webauthn-register"

class WebTestBase(unittest.TestCase, metaclass=ABCMeta):
    """
    Base Class for web app tests
    """

    def __init__(self, name):
        super().__init__(name)
        self.app: Flask = None
        self.app_client: FlaskClient = None
        self.user_info_mock = None
        self.jwt_mock = None

    def _create_app(self):
        self.app = create_app()
        self.app.testing = True
        self.app_client = self.app.test_client()
        self.app_client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer 1234'

    def setUp(self):
        self.addCleanup(patch.stopall)
        self.keycloak_api_init_mock = patch("app_factory.keycloak_client.init_app").start()
        self.keycloak_api_mock = patch("api_definitions.keycloak_client").start()
        self.keycloak_api_mock.CREDENTIAL_TYPE_OTP = CREDENTIAL_TYPE_OTP
        self.keycloak_api_mock.CREDENTIAL_TYPE_WEBAUTHN = CREDENTIAL_TYPE_WEBAUTHN
        self.keycloak_api_mock.REQUIRED_ACTION_CONFIGURE_OTP = REQUIRED_ACTION_CONFIGURE_OTP
        self.keycloak_api_mock.REQUIRED_ACTION_WEBAUTHN_REGISTER = REQUIRED_ACTION_WEBAUTHN_REGISTER
        self._create_app()
        self.mock_auth()

    def mock_auth(self, app_name: str = "authorization-service-api", roles=None):
        if not roles:
            roles = []
        self.jwt_mock = patch("authlib_helpers.decorators.jwt").start()
        self.user_info_mock = patch("authlib_helpers.decorators.UserInfo").start()
       
        self.jwt_mock.return_value.decode.return_value = {"decoded": True}
        self.user_info_mock.return_value = {
            "azp": app_name,
            "resource_access": {
                "keycloak-rest-adapter": {
                    "roles": roles
                }
            }
        }
