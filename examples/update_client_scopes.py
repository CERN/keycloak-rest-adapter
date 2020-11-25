import requests
import sys
import json

args = sys.argv[0:]
if not args:
    print("USAGE: ./script.py")
    sys.exit(1)

client_id = "test"
scope_id = "f0a5a82f-54e0-481c-96cd-10857af03ca3"

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

endpoint = "http://localhost:5000/api/v1.0/client/saml/{0}".format(client_id)

print("ALL SCOPES")
ret = requests.get(
    "http://localhost:5000/api/v1.0/client/scopes",
    headers={"Authorization": "Bearer {}".format(token)},
)
print(json.dumps(ret.json(), indent=2))
print(ret.json()[0])

print("DEFAULT SCOPES")
ret2 = requests.get(
    "http://localhost:5000/api/v1.0/client/{0}/default-scopes".format(client_id),
    headers={"Authorization": "Bearer {}".format(token)},
)
print(json.dumps(ret2.json(), indent=2))

print(json.dumps(requests.put(
    "http://localhost:5000/api/v1.0/client/{0}/default-scopes/{1}".format(client_id, scope_id),
    headers={"Authorization": "Bearer {}".format(token)},
).json(), indent=2))

print(json.dumps(requests.get(
    "http://localhost:5000/api/v1.0/client/{0}/default-scopes".format(client_id),
    headers={"Authorization": "Bearer {}".format(token)},
).json(), indent=2))

print(json.dumps(requests.delete(
    "http://localhost:5000/api/v1.0/client/{0}/default-scopes/{1}".format(client_id, scope_id),
    headers={"Authorization": "Bearer {}".format(token)},
).json(), indent=2))

print(json.dumps(requests.get(
    "http://localhost:5000/api/v1.0/client/test/default-scopes",
    headers={"Authorization": "Bearer {}".format(token)},
).json(), indent=2))

print("BAD REQUESTS")
print(json.dumps(requests.get(
    "http://localhost:5000/api/v1.0/client/{0}/default-scopes/".format("hello"),
    headers={"Authorization": "Bearer {}".format(token)},
).json(), indent=2))
