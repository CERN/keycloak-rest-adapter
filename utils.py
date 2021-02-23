from typing import Dict
from xml.etree import ElementTree as ET
import logging
from flask import make_response, jsonify, current_app

JSON_MIME_TYPE = "application/json"


def get_supported_protocols() -> Dict[str, str]:
    return current_app.config["AUTH_PROTOCOLS"]


def json_response(data="", status=200, headers=None):
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


def validate_protocol(protocol, supported_protocols: Dict[str, str]):
    """
    Checks if the protocol is contained in the supported methods
    :param protocol: the protocol
    :param supported_protocols: a dict
    """
    if protocol not in supported_protocols:
        return json_response(
            "The protocol is invalid. Accepted protocols: {}".format(
                str(supported_protocols)
            ),
            400,
        )


def validate_protocol_data(data, supported_protocols: Dict[str, str]):
    """
    Checks if the protocol in the passed dictionary is correct
    """
    if "protocol" not in data:
        return json_response(
            "The request is missing 'protocol'. It must be passed in the form data", 400
        )
    return validate_protocol(data["protocol"], supported_protocols)


class ResourceNotFoundError(Exception):
    pass

class KeycloakAPIError(Exception):
    def __init__(self, status_code, message):
        obj = {"status_code": status_code, "message": message}
        super().__init__(obj)
        self.status_code = status_code
        self.message = message
