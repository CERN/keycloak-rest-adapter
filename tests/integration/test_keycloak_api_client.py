import os
import unittest
from model import Client
from flask import Flask
from keycloak_api_client.keycloak import KeycloakAPIClient
from tests.utils.keycloak_docker_tools import (
    create_keycloak_docker,
    tear_down_keycloak_docker,
)
from tests.utils.tools import in_ci_job, run_integration_tests

SAML_ENTITY_ID = "http://cristi-nuc.cern.ch:5000/saml/metadata/"

SAML_DESCRIPTOR = f"""
<EntityDescriptor ID="_75740d48-d767-4b02-909b-6e0ac4018d9c" entityID="{SAML_ENTITY_ID}" cacheDuration="PT1H"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://cristi-nuc.cern.ch:5000/saml/acs/" index="0" isDefault="true"/>
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://cristi-nuc.cern.ch:5000/saml/acs/" index="1" isDefault="false"/>
    </SPSSODescriptor>
</EntityDescriptor>
"""

OIDC_CLIENT_ID = "test-potato"
# address scope is inbuilt in Keycloak
OIDC_CLIENT_TEST_SCOPE = "address"

TEARDOWN = bool(os.getenv("TEARDOWN_CONTAINER", ""))


@unittest.skipUnless(
    run_integration_tests(), "Skipped: RUN_INTEGRATION env variable was not set"
)
class TestKeycloakApiClient(unittest.TestCase):
    """
    Integration tests against the Keycloak API
    """

    server = "http://localhost:8081"
    app = None

    @classmethod
    def setUpClass(cls):
        if in_ci_job():
            cls.server = "http://keycloak:8080"
        else:
            create_keycloak_docker()

    def setUp(self):
        config = {
            "KEYCLOAK_SERVER": self.server,
            "KEYCLOAK_REALM": "test",
            "KEYCLOAK_CLIENT_ID": "keycloak-rest-adapter",
            "KEYCLOAK_CLIENT_SECRET": "42ac0602-a08e-49f7-9b92-44afd622d29c",
            "INTERNAL_DOMAINS_REGEX": r"(cern\.ch$|\.cern$|localhost$|localhost.localdomain$|127.0.0.1$|[::1]$)",
            "EXTERNAL_SCOPE_OIDC": "external",
            "EXTERNAL_SCOPE_SAML": "saml-external",
            "CLIENT_DEFAULTS": {
                "openid": {
                    "protocolMappers": [],
                    "webOrigins": ["+"],
                    "consentRequired": False,
                    "defaultClientScopes": [
                        "email",
                    ]
                },
                "saml": {
                    "protocolMappers": [],
                    "consentRequired": False,
                    "defaultClientScopes": [
                        "role_list",
                    ],
                },
            }
        }
        self.app = Flask(__name__)
        self.app.config.update(config)
        self.client = KeycloakAPIClient()
        self.client.init_app(self.app)
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
        self.client.delete_client_by_client_id(SAML_ENTITY_ID)

    def test_create_oidc_client(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])
        self.assertEqual("openid-connect", created["protocol"])

    def test_create_saml_client_with_xml_converter(self):
        client_description = self.client.client_description_converter(SAML_DESCRIPTOR)
        self.assertIsNotNone(client_description)
        self.assertEqual("saml", client_description["protocol"])
        with self.app.app_context():
            created = self.client.create_new_client(Client(client_description, protocol="saml"))
        self.assertIsNotNone(created)
        self.assertEqual(SAML_ENTITY_ID, created["clientId"])
        self.assertEqual("saml", created["protocol"])
        self.assertListEqual(
            ["http://cristi-nuc.cern.ch:5000/saml/acs/"], created["redirectUris"]
        )

    def test_refresh_token_oidc_client(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        recreated_token = self.client.regenerate_client_secret(OIDC_CLIENT_ID).json()
        self.assertIsNotNone(recreated_token)
        self.assertTrue("value" in recreated_token)
        self.assertTrue("type" in recreated_token)
        self.assertEqual("secret", recreated_token["type"])

    def test_delete_not_found(self):
        delete_response = self.client.delete_client_by_client_id("some_missing_client")

        self.assertIsNone(delete_response)

    def test_recreate_secret_oidc_client(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        recreated_token = self.client.regenerate_client_secret(OIDC_CLIENT_ID).json()
        self.assertIsNotNone(recreated_token)
        self.assertTrue("value" in recreated_token)
        self.assertTrue("type" in recreated_token)
        self.assertEqual("secret", recreated_token["type"])

    def test_update_oidc_client_updates_properties(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        description = "some new description"
        updated = Client(created, app=self.app)
        updated.definition["description"] = description
        with self.app.app_context():
            response = self.client.update_client_properties(
                OIDC_CLIENT_ID, updated
            )
        self.assertEqual(OIDC_CLIENT_ID, response.definition["clientId"])
        self.assertEqual(description, response.definition["description"])

    def test_set_fine_grained_perms(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        response = self.client.set_client_fine_grain_permission(created["id"], False)
        self.assertEqual(200, response.status_code)

    def test_get_client_by_client_id_found(self):
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        response = self.client.get_client_by_client_id(OIDC_CLIENT_ID)
        self.assertIsNotNone(response)
        self.assertEqual(response["id"], created["id"])

    def test_get_client_by_client_id_not_found(self):
        # act
        response = self.client.get_client_by_client_id(OIDC_CLIENT_ID)
        self.assertFalse(response)

    @unittest.skip("Throwing 500 on the latest keycloak version")
    def test_create_client_policy(self):
        # prepare
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        with self.app.app_context():
            created = self.client.create_client_policy(
                created["id"], "test-policy", "some policy"
            )
        self.assertEqual(200, created.status_code)

    @unittest.skip("No permissions enabled by default. We should enable them in the KC container so we can test for a successful response.")
    def test_get_auth_permission_by_name(self):
        # act
        resp = self.client.get_auth_permission_by_name("view.permission.client.08b7ddce-8cc2-4850-87f9-70a3a0e6b533")

        # assert
        self.assertIsNotNone(resp)
        self.assertEqual("view.permission.client.08b7ddce-8cc2-4850-87f9-70a3a0e6b533", resp[0]['name'])

    def test_get_all_clients(self):
        # prepare
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        resp = self.client.get_all_clients()
        self.assertTrue(len(resp) > 0)
        self.assertTrue(any(r["clientId"] == OIDC_CLIENT_ID for r in resp))

    def test_get_user_by_username(self):
        # prepare
        try:
            existing = self.client.get_user_by_username("test-user")
            self.client.delete_user(existing["id"])
        except Exception:
            pass
        # act
        response = self.client.create_user("test-user")

        self.assertEqual(201, response.status_code)
        existing = self.client.get_user_by_username("test-user")
        self.assertIsNotNone(existing)
        response = self.client.delete_user(existing["id"])
        self.assertEqual(204, response.status_code)

    def test_update_user_properties(self):
        # prepare
        try:
            existing = self.client.get_user_by_username("test-user")
            self.client.delete_user(existing["id"])
        except Exception:
            pass

        response = self.client.create_user("test-user")
        self.assertEqual(201, response.status_code)

        # act
        ret = self.client.update_user_properties(
            "test-user", self.client.realm, **{"enabled": True}
        )

        self.assertIsNotNone(ret)
        # import ipdb; ipdb.set_trace()
        self.assertEqual(True, ret["enabled"])
        response = self.client.delete_user(ret["id"])
        self.assertEqual(204, response.status_code)

    def test_get_scopes(self):
        # act
        response = self.client.get_scopes()
        self.assertIsNotNone(response)

    def test_get_client_scopes(self):
        # prepare
        with self.app.app_context():
            created = self.client.create_new_openid_client(
                Client({"protocol": "openid", "clientId": OIDC_CLIENT_ID})
            )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        response = self.client.get_client_default_scopes(OIDC_CLIENT_ID)

        # assert
        self.assertIsNotNone(response)
        self.assertTrue(len(response) > 0)

    @classmethod
    def tearDownClass(cls):
        if not in_ci_job() and TEARDOWN:
            print("Tearing down Keycloak")
            tear_down_keycloak_docker()


if __name__ == "__main__":
    unittest.main()
