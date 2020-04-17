# API CONFIG
API_VERSION = "v1.0"

# Keycloak
KEYCLOAK_SERVER = "https://keycloak-dev.cern.ch"
# Note this must be master
KEYCLOAK_REALM = "master"
KEYCLOAK_CLIENT_ID = "keycloak-rest-adapter"
# Note that this must be the client secret of the "keycloak-rest-adapter" client in
# the "master" realm
KEYCLOAK_CLIENT_SECRET = "DELETED"

# OAuth config (for the Swagger UI)
# The client ID used to login from the UI
SWAGGER_UI_OAUTH_CLIENT_ID = "keycloak-rest-adapter"

# OIDC config
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
