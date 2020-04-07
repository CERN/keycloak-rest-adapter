import requests
import sys
import json

args = sys.argv[1:]
if not args:
    print("USAGE: ./script.py $TOKEN")
    sys.exit(1)

endpoint = "http://localhost:5000/api/v1.0/client/saml"


f = open("/home/cristi/Downloads/good-registration-cristi-nuc.xml")

resp = requests.post(
    endpoint,
    data={"definition": f.read()},
    headers={"Authorization": "Bearer {}".format(args[0])},
)
print("Status: {}".format(resp.status_code))
print(json.dumps(resp.json(), indent=2))
