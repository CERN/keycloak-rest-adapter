# API CONFIG
API_VERSION = "v1.0"

# Keycloak
KEYCLOAK_SERVER = "https://keycloak-dev.cern.ch"
KEYCLOAK_CLIENT_ID = "keycloak-rest-adapter"
# Note that this must be the client secret of the "keycloak-rest-adapter" client in
# the "master" realm
KEYCLOAK_CLIENT_SECRET = "DELETED"

# Note this is the realm where clients will be created
KEYCLOAK_REALM = "cern"

# OAuth config (for the Swagger UI)
# The client ID used to login from the UI
OAUTH_AUTH_URL = "https://keycloak-dev.cern.ch/auth/realms/cern/protocol/openid-connect/auth"
OIDC_JWKS_URL = "https://keycloak-dev.cern.ch/auth/realms/cern/protocol/openid-connect/certs"
OIDC_ISSUER = "https://keycloak-dev.cern.ch/auth/realms/cern"

SWAGGER_UI_OAUTH_CLIENT_ID = "keycloak-rest-adapter"

# OIDC config
# The client ID used to validate incoming calls
OIDC_CLIENT_ID = "keycloak-rest-adapter"
OIDC_REALM = "cern"
OAUTH_AUTHORIZATIONS = {
    "oauth2": {
        "type": "oauth2",
        "flow": "authorizationCode",
        # "authorizationUrl": None,
        # "tokenUrl": None,
        # Set this in order to not have it by default keycloak server + realm
    }
}

# Client default mappers
CLIENT_DEFAULTS = {
    "openid": {
        "protocolMappers": [],
        "webOrigins": ["+"],
        "consentRequired": False,
        "defaultClientScopes": [
            "cern-login-info",
            "profile",
            "email",
            "authz-roles",
            "web-origins",
        ],
        "optionalClientScopes": [
            "address",
            "offline_access",
            "phone",
        ]
    },
    "saml": {
        "protocolMappers": [],
        "consentRequired": False,
        "defaultClientScopes": [
            "saml-cern-login-info",
            "saml-cern-profile",
            "saml-email",
            "saml-roles",
        ],
    },
}

# Authentication protocols
AUTH_PROTOCOLS = {"saml": "definition", "openid": "clientId"}

# Auth configs
AUTH_AUTHORIZED_APPS = ["authorization-service-api"]
AUTH_API_ACCESS_ROLE = "admin"
AUTH_USER_ACTIONS_ROLE = "user"
AUTH_USER_ACTIONS_MFA_ROLE = "user_mfa"

# Internal domains (i.e. CERN & Localhost)
INTERNAL_DOMAINS_REGEX = r"(.*\.cern\.ch$|.*\.cern$|localhost$|localhost.localdomain$|127.0.0.1$|::1$)"

EXTERNAL_SCOPE_OIDC = 'external'
EXTERNAL_SCOPE_SAML = 'saml-external'
