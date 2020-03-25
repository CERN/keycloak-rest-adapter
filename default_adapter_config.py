# API CONFIG
API_VERSION = "v1.0"
API_URL_PREFIX = "/api/{}".format(API_VERSION)

# Keycloak
KEYCLOAK_SERVER = "https://keycloak-dev.cern.ch"
KEYCLOAK_REALM = "master"
KEYCLOAK_CLIENT_ID = "keycloak-rest-adapter"
# Override this in the config
# Note that this must be the client secret of the "keycloak-rest-adapter" client in
# the "master" realm, not in the "cern" realm.
KEYCLOAK_CLIENT_SECRET = None

# OAuth config (for the Swagger UI)
# Where the swagger UI redirects back after successful login
SWAGGER_UI_OAUTH_REDIRECT_URL = "http://localhost:5000/oauth2-redirect.html"
# The client ID used to login from the UI
SWAGGER_UI_OAUTH_CLIENT_ID = "keycloak-rest-adapter"

# "https://localhost:8443/auth/realms/master/token"
# Where the Swagger UI should authenticate to
OAUTH_AUTH_URL = f"{KEYCLOAK_SERVER}/auth/realms/cern/protocol/openid-connect/auth"
# Whether to serve swagger on http or https
OAUTH_HTTPS_SWAGGER = True

# OIDC config
# The 'iss' field in the token should match this
OIDC_ISSUER = "https://keycloak-dev.cern.ch/auth/realms/cern"
# Configuration URL for all the keys of the Keycloak server
OIDC_JWKS_URL = "https://keycloak-dev.cern.ch/auth/realms/cern/protocol/openid-connect/certs"
# The client ID used to validate incoming calls
OIDC_CLIENT_ID = "keycloak-rest-adapter"
OAUTH_AUTHORIZATIONS = {
    "oauth2": {
        "type": "oauth2",
        "flow": "implicit",
        # "authorizationUrl": None,
        # Set this in order to not have it by default keycloak server + realm
    }
}

# Client default mappers
CLIENT_DEFAULTS = {
    "openid": {
        "protocolMappers": [],
        "webOrigins": ["+"],
        "consentRequired": False
    },
    "saml": {
        "protocolMappers": [],
        "consentRequired": False
    }
}

# Authentication protocols
AUTH_PROTOCOLS = {
    "saml": "definition",
    "openid": "clientId"
}

# Auth configs
AUTH_AUTHORIZED_APPS = ["authorization-service-api"]
AUTH_API_ACCESS_ROLE = "admin"
AUTH_USER_ACTIONS_ROLE = "user"
AUTH_USER_ACTIONS_MFA_ROLE = "user_mfa"
