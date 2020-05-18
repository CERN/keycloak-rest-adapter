import json
import os
import requests
import sys
import unittest
import time

from keycloak_api_client.keycloak import KeycloakAPIClient
from tests.utils.keycloak_docker_tools import (
    create_keycloak_docker,
    tear_down_keycloak_docker,
)

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

TEARDOWN = False


def in_ci_job():
    return os.environ.get("CI", False)


class TestKeycloakApiClient(unittest.TestCase):
    server = "http://localhost:8081"

    @classmethod
    def setUpClass(cls):
        if in_ci_job():
            cls.server = "http://keycloak:8080"
        else:
            create_keycloak_docker()

    def setUp(self):
        self.client = KeycloakAPIClient(
            self.server,
            "test",
            "keycloak-rest-adapter",
            "111d61ea-b890-4285-b742-e0c417c5e513",
        )

    def test_create_oidc_client(self):
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
        created = self.client.create_new_openid_client(
            **{"protocol": "openid", "clientId": OIDC_CLIENT_ID}
        )
        self.assertEqual(OIDC_CLIENT_ID, created["clientId"])

    def test_create_saml_client_with_xml_converter(self):
        self.client.delete_client_by_client_id(SAML_ENTITY_ID)
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
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
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
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
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
        self.client.delete_client_by_client_id(OIDC_CLIENT_ID)
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

    @classmethod
    def tearDownClass(cls):
        if not in_ci_job() and TEARDOWN:
            print("Tearing down Keycloak")
            tear_down_keycloak_docker()


if __name__ == "__main__":
    unittest.main()
