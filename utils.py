from flask import make_response, jsonify
import os
import json
from xml.etree import ElementTree as ET


config_dir = os.path.join(os.getcwd(), "config")
auth_protocols_file = "{0}/auth_protocols.json".format(config_dir)

auth_protocols = {}
with open(auth_protocols_file, "r") as f:
    auth_protocols = json.load(f)

SUPPORTED_PROTOCOLS = list(auth_protocols.keys())


def json_response(data="", status=200, headers=None):
    JSON_MIME_TYPE = "application/json"
    headers = headers or {}
    if "Content-Type" not in headers:
        headers["Content-Type"] = JSON_MIME_TYPE
    json_data = jsonify({"data": data})
    return make_response(json_data, status, headers)


def get_request_data(request):
    """
    Gets the data from the request
    """
    # https://stackoverflow.com/questions/10434599/how-to-get-data-received-in-flask-request/25268170
    data = request.form.to_dict() if request.form else request.get_json()
    if not data:
        return {}
    return data


def is_xml(data):
    """
   Check if string is XML or not by trying to parse it
   Empty strings also raise Parse error
   """
    try:
        ET.fromstring(data)
        return True
    except ET.ParseError:
        return False


def validate_protocol(protocol):
    """
        Checks if the protocol is contained in the supported methods
        """
    if not protocol in SUPPORTED_PROTOCOLS:
        return json_response(
            "The protocol is invalid. Accepted protocols: {}".format(
                str(SUPPORTED_PROTOCOLS)
            ),
            400,
        )


def validate_protocol_data(data):
    """
    Checks if the protocol in the passed dictionary is correct
    """
    if not "protocol" in data:
        return json_response(
            "The request is missing 'protocol'. It must be passed in the form data", 400
        )
    return validate_protocol(data["protocol"])


class ResourceNotFoundError(Exception):
    pass
