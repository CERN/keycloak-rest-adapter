import unittest
import json
from unittest.mock import MagicMock, patch

from tests.utils.tools import API_ROOT, WebTestBase


class TestClientCreationApi(WebTestBase):
    """
    Test the client details endpoints of the API
    """

    client_id = "target"

    def _get_endpoint(self, protocol: str):
        return f"{API_ROOT}/client/{protocol}"

    def _get_endpoint_no_protocol(self):
        return f"{API_ROOT}/client"

    def _mock_oidc_call(self):
        return {
            "protocolMappers": [
                {
                    "protocol": "openid-connect",
                    "config": {
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                        "included.client.audience": self.client_id,
                    },
                    "name": "audience",
                    "protocolMapper": "oidc-audience-mapper",
                }
            ],
            "redirectUris":["ch.cern.app:/dasd", "https://test.cern.ch", "https://127.0.0.1:3000"],
            "webOrigins": ['+'],
            "consentRequired": False,
            "clientId": self.client_id,
            "protocol": 'openid'
        }

    def _mock_oidc_call_consent_required(self):
        return {
            "protocolMappers": [
                {
                    "protocol": "openid-connect",
                    "config": {
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                        "included.client.audience": self.client_id,
                    },
                    "name": "audience",
                    "protocolMapper": "oidc-audience-mapper",
                }
            ],
            "redirectUris": ["ch.test.app:/dasd", "https://test.com"],
            "webOrigins": ['+'],
            "consentRequired": True,
            "clientId": self.client_id,
            "protocol": 'openid'
        }

    def test_create_invalid_protocol(self):
        # act
        resp = self.app_client.post(self._get_endpoint_no_protocol(),
            data=json.dumps({"protocol": "testprot"}),
            content_type='application/json')
        # assert

        self.assertEqual(400, resp.status_code)

    def test_create_invalid_protocol_in_uri(self):
        # act
        resp = self.app_client.post(self._get_endpoint("testprot"))
        # assert

        self.assertEqual(400, resp.status_code)

    def test_create_unsupported_protocol(self):
        # prepare
        self.app.config['AUTH_PROTOCOLS'] = {'potato': "clientId"}

        # act
        resp = self.app_client.post(self._get_endpoint("potato"),
            data=json.dumps({"clientId": self.client_id}),
            content_type='application/json')

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("Unsupported client protocol 'potato'".casefold() in resp.json['data'].casefold())

    # OIDC endpoints
    def test_create_missing_required_param_openid(self):
        # act
        resp = self.app_client.post(self._get_endpoint("openid"),
            data=json.dumps({}),
            content_type='application/json')
        # assert

        self.assertEqual(400, resp.status_code)
        self.assertTrue("the request is missing 'clientId'".casefold() in resp.json['data'].casefold())

    def test_create_oidc_exception_thrown(self):
        # prepare
        self.keycloak_api_mock.create_new_client.return_value = MagicMock()

        # act
        resp = self.app_client.post(self._get_endpoint("openid"),
            data=json.dumps({"clientId": self.client_id}),
            content_type='application/json')

        # assert
        self.assertEqual(400, resp.status_code)
        self.assertTrue("Unknown error creating client".casefold() in resp.json['data'].casefold())

    def test_consent_enabled_external(self):
        mock_creation = {"clientId": self.client_id}
        expected_call = self._mock_oidc_call_consent_required()
        self.keycloak_api_mock.create_new_client.return_value = mock_creation

        # act (redirectUris outside CERN)
        resp = self.app_client.post(self._get_endpoint("openid"),
            data=json.dumps({"clientId": self.client_id, "redirectUris":["ch.test.app:/dasd", "https://test.com"]}),
            content_type='application/json')

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual(mock_creation, resp.json)
        self.keycloak_api_mock.create_new_client.assert_called_with(**expected_call)

    def test_create_oidc_works_fine(self):
        # prepare
        mock_creation = {"clientId": self.client_id}
        expected_call = self._mock_oidc_call()
        self.keycloak_api_mock.create_new_client.return_value = mock_creation

        # act
        resp = self.app_client.post(self._get_endpoint("openid"),
            data=json.dumps({"clientId": self.client_id, "redirectUris":["ch.cern.app:/dasd", "https://test.cern.ch", "https://127.0.0.1:3000"]}),
            content_type='application/json')

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual(mock_creation, resp.json)
        self.keycloak_api_mock.create_new_client.assert_called_with(**expected_call)

    # SAML endpoints

    def test_create_missing_required_param_saml(self):
        # act
        resp = self.app_client.post(self._get_endpoint("saml"),
            data=json.dumps({}),
            content_type='application/json')
        # assert

        self.assertEqual(400, resp.status_code)
        self.assertTrue("the request is missing 'definition'".casefold() in resp.json['data'].casefold())

    def test_create_saml_fake_xml(self):
        # act
        resp = self.app_client.post(self._get_endpoint("saml"),
            data=json.dumps({"definition": "<datavalue</data>"}),
            content_type='application/json')
        # assert

        self.assertEqual(400, resp.status_code)
        self.assertTrue("Unsupported client protocol".casefold() in resp.json['data'].casefold())

    def test_create_saml_good_xml(self):
        # prepare
        mock_creation = {"clientId": self.client_id}
        creation_call_expected = {"clientId": self.client_id, "protocolMappers": [], "protocol": "saml", "consentRequired": False}
        xml_payload = "<clientId>value</clientId>"
        self.keycloak_api_mock.client_description_converter.return_value = {"clientId": self.client_id}
        self.keycloak_api_mock.create_new_client.return_value = mock_creation

        # act
        resp = self.app_client.post(self._get_endpoint("saml"),
            data=json.dumps({"definition": xml_payload}),
            content_type='application/json')

        # assert
        self.assertEqual(200, resp.status_code)
        self.assertDictEqual(mock_creation, resp.json)
        self.keycloak_api_mock.client_description_converter.assert_called_with(xml_payload)
        self.keycloak_api_mock.create_new_client.assert_called_with(**creation_call_expected)
