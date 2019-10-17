import requests
from authlib.jose import jwk, jwt
from authlib.jose.errors import InvalidClaimError
from authlib.oidc.core import ImplicitIDToken, UserInfo
from flask import current_app, request

from utils import json_response

AUTHORIZED_APPS = ['authorization-service-api']
API_ACCESS_ROLE = 'admin'


class ImplicitIDTokenNoNonce(ImplicitIDToken):
    """
    Don't validate the nonce claim as it's not coming with the token
    """

    ESSENTIAL_CLAIMS = ["iss", "sub", "aud", "exp", "iat"]

    def validate_azp(self):
        azp = self.get('azp')
        client_id = self.params.get('client_id')
        if azp and (azp not in AUTHORIZED_APPS or client_id != azp):
            raise InvalidClaimError('azp')


def validate_api_access(access_token):
    """
    Verify if the caller entity is allowed to call the API
    :param access_token: The access token that was parsed for the API
    :return:
    """
    try:
        if access_token['azp'] in AUTHORIZED_APPS:
            return True
        elif API_ACCESS_ROLE in access_token['resource_access'][current_app.config['OIDC_CLIENT_ID']]['roles']:
            return True
    except Exception as e:
        current_app.logger.error(e)
    return False


def parse_id_token(id_token):
    """
    Parses an ID token and returns it as a set of user info claims
    :param id_token:
    :return:
    """

    def load_key(header, payload):
        jwk_set = requests.get(current_app.config["OIDC_JWKS_URL"]).json()
        return jwk.loads(jwk_set, header.get("kid"))

    claims_params = {"client_id": current_app.config["OIDC_CLIENT_ID"]}
    claims_cls = ImplicitIDTokenNoNonce
    claims_options = {
        "iss": {"values": [current_app.config["OIDC_ISSUER"]]}
    }
    claims = jwt.decode(
        id_token,
        key=load_key,
        claims_cls=claims_cls,
        claims_options=claims_options,
        claims_params=claims_params,
    )
    claims.validate(leeway=120)
    return UserInfo(claims)


def oidc_validate(func):
    """
    Decorator for validation of the auth token
    """

    def function_wrapper(*args, **kwargs):
        try:
            auth_header = request.headers["Authorization"]
            token = auth_header.split("Bearer")[1].strip()
            user_info = parse_id_token(token)
            print(user_info)
            if not validate_api_access(user_info):
                current_app.logger.error("User is not allowed to access the API")
                return json_response("Unauthorized", 401)
        except Exception as e:
            current_app.logger.error(f"Authentication error: {e}")
            return json_response("Unauthorized", 401)

        return func(*args, **kwargs)

    return function_wrapper
