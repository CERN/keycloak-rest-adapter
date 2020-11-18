import requests
import sys
import json

args = sys.argv[1:]
if not args:
    print("USAGE: ./script.py $FILE")
    sys.exit(1)


# Get token
keycloak_endpoint = "https://keycloak-dev.cern.ch/auth/realms/cern/api-access/token"
token_resp = requests.post(
    keycloak_endpoint,
    data={
        "grant_type": "client_credentials",
        "client_id": "authorization-service-api",
        # MAKE SURE THE SECRET IS DELETED
        "client_secret": "DELETED",
        "audience": "keycloak-rest-adapter"
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
token = token_resp.json()['access_token']
print("Token: {}".format(token))

endpoint = "http://localhost:5000/api/v1.0/client/saml"

f = open(args[0])

resp = requests.post(
    endpoint,
    json={
        "definition": f.read(),
        "defaultClientScopes": ["saml-udemy"]
    },
    headers={"Authorization": "Bearer {}".format(token)},
)
print("Status: {}".format(resp.status_code))
print(json.dumps(resp.json(), indent=2))
