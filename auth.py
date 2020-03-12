from importlib.resources import Resource
from logging import Logger
from typing import List

from authlib.oidc.core import ImplicitIDToken, UserInfo
from authlib_helpers import AuthLibHelper, json_response
from authlib_helpers.decorators import ImplicitIDTokenNoNonce


class UserAuthLibHelper(AuthLibHelper):
    """
    Authlib helper extension adding a second authentication decorator for the rest adapter
    """

    def __init__(self, user_access_role: str, access_role: str, client_id: str, authorized_apps: List[str],
                 oidc_jwks_url: str, oidc_issuer: str, logger: Logger,
                 claims_class: ImplicitIDToken = ImplicitIDTokenNoNonce):
        """
        Constructor
        :param user_access_role: the role needed in order to perform self-service (user) operations
        :param access_role: the role needed in order to have full API access
        :param client_id: the ID of the client which is behind OIDC
        :param authorized_apps: a list of apps that are authorized to access this API (via token exchange)
        :param oidc_jwks_url: the URL to the JWKS url
        :param oidc_issuer: the issuer of the token
        :param logger: the logger for the application
        :param claims_class: the class used for validation of claims, could be something else in case of specific needs
        """
        super(UserAuthLibHelper, self).__init__(
            access_role=access_role,
            client_id=client_id,
            authorized_apps=authorized_apps,
            oidc_jwks_url=oidc_jwks_url,
            oidc_issuer=oidc_issuer,
            logger=logger,
            claims_class=claims_class
        )
        self.user_access_role = user_access_role

    def _validate_user_access(self, access_token: UserInfo, username: str) -> bool:
        """
        Verify if the caller entity is allowed to call the API
        :param access_token: The access token that was parsed for the API
        :param username: The username expected in the access token
        :return: Boolean
        """
        try:
            if self.user_access_role in access_token["resource_access"][self.oidc_client_id]["roles"]:
                return access_token["sub"] == username
        except Exception as e:
            self.logger.error(e)
        return False

    # Decorators
    def oidc_validate_user_or_api(self, func):
        """
        Decorator for validation of the auth token. It needs to decorate a flask_restplus method inside a class.
        """

        def function_wrapper(resource: Resource, username: str, *args, **kwargs):
            try:
                user_info = self._get_user_info_from_token_header()
                self.logger.debug(user_info)
                user_access = self._validate_user_access(user_info, username)
                api_access = self._validate_api_access(user_info)
                if not user_access and not api_access:
                    self.logger.error(
                        "User is not authorized to access or modify the resource"
                    )
                    return json_response("Unauthorized", 401)
            except Exception as e:
                self.logger.error(f"Authentication error: {e}")
                return json_response("Unauthorized", 401)
            return func(resource, username, *args, **kwargs)

        return function_wrapper
