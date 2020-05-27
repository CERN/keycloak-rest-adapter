import os
import unittest

from keycloak_api_client.keycloak import KeycloakAPIClient
from tests.utils.keycloak_docker_tools import (create_keycloak_docker,
                                               tear_down_keycloak_docker)
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

TEARDOWN = bool(os.getenv("TEARDOWN_CONTAINER", ""))


@unittest.skipUnless(run_integration_tests(), "Skipped: RUN_INTEGRATION env variable was not set")
class TestKeycloakApiClient(unittest.TestCase):
    """
    Integration tests against the Keycloak API
    """
    server = "http://localhost:8081"

    @classmethod
    def setUpClass(cls):
        if in_ci_job():
            cls.server = "http://keycloak:8080"
        else:
            create_keycloak_docker()

    def setUp(self):
        self.client = KeycloakAPIClient()

        class _app:
            config = {
                "KEYCLOAK_SERVER": self.server,
                "KEYCLOAK_REALM": "test",
                "KEYCLOAK_CLIENT_ID": "keycloak-rest-adapter",
                "KEYCLOAK_CLIENT_SECRET": "42ac0602-a08e-49f7-9b92-44afd622d29c",
            }
        self.client.init_app(_app)
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
        self.client.delete_client_by_client_id(SAML_ENTITY_ID)

    def test_create_oidc_client(self):
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

    def test_create_saml_client_with_xml_converter(self):
        client_description = self.client.client_description_converter(SAML_DESCRIPTOR)
        self.assertIsNotNone(client_description)
        self.assertEqual("saml", client_description["protocol"])

        created = self.client.create_new_client(**client_description)
        self.assertIsNotNone(created)
        self.assertEqual(SAML_ENTITY_ID, created["clientId"])
        self.assertListEqual(
            ["http://cristi-nuc.cern.ch:5000/saml/acs/"], created["redirectUris"]
        )

    def test_refresh_token_oidc_client(self):
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
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
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        recreated_token = self.client.regenerate_client_secret(OIDC_CLIENT_ID).json()
        self.assertIsNotNone(recreated_token)
        self.assertTrue("value" in recreated_token)
        self.assertTrue("type" in recreated_token)
        self.assertEqual("secret", recreated_token["type"])

    def test_update_oidc_client_updates_properties(self):
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        description = "some new description"
        updated = self.client.update_client_properties(
            OIDC_CLIENT_ID, description=description
        )
        print(updated)
        self.assertEqual(OIDC_CLIENT_ID, updated["clientId"])
        self.assertEqual(description, updated["description"])

    def test_set_fine_grained_perms(self):
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        response = self.client.set_client_fine_grain_permission(created["id"], False)
        self.assertEqual(200, response.status_code)

    def test_get_client_by_client_id_found(self):
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act 
        response = self.client.get_client_by_client_id(OIDC_CLIENT_ID)
        self.assertIsNotNone(response)
        self.assertEqual(response['id'], created['id'])

    def test_get_client_by_client_id_not_found(self):
        # act 
        response = self.client.get_client_by_client_id(OIDC_CLIENT_ID)
        self.assertFalse(response)

    @unittest.skip("Throwing 500 on the latest keycloak version")
    def test_create_client_policy(self):
        # prepare
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        created = self.client.create_client_policy(created["id"], "test-policy", "some policy")
        self.assertEqual(200, created.status_code)

    def test_get_auth_permission_by_name(self):
        # act
        resp = self.client.get_auth_permission_by_name("test-perm")

        # assert
        self.assertIsNotNone(resp)
        self.assertTrue("error" in resp)

    def test_get_all_clients(self):
        # prepare
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

        # act
        resp = self.client.get_all_clients()
        self.assertTrue(len(resp) > 0)
        self.assertTrue(any(r['clientId'] == OIDC_CLIENT_ID for r in resp))

    def test_get_user_by_username(self):
        # prepare
        try:
            existing = self.client.get_user_by_username("test-user")
            self.client.delete_user(existing["id"])
        except:
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
        except:
            pass

        response = self.client.create_user("test-user")
        self.assertEqual(201, response.status_code)

        # act
        ret = self.client.update_user_properties("test-user", self.client.realm, **{"enabled":  True})

        self.assertIsNotNone(ret)
        # import ipdb; ipdb.set_trace()
        self.assertEqual(True, ret["enabled"])
        response = self.client.delete_user(ret["id"])
        self.assertEqual(204, response.status_code)

    @classmethod
    def tearDownClass(cls):
        if not in_ci_job() and TEARDOWN:
            print("Tearing down Keycloak")
            tear_down_keycloak_docker()


if __name__ == "__main__":
    unittest.main()
