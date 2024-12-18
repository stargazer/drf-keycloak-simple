""" module for app specific keycloak connection """
from typing import Dict, List
import traceback
import logging

from keycloak import KeycloakOpenID

from .settings import api_settings
from . import __title__


log = logging.getLogger(__title__)


class OIDCConfigException(Exception):
    pass


def get_request_oidc_config(host: str) -> dict:
    """ Determine client config from request host.
        :param host: Hostname

        KEYCLOAK_MULTI_OIDC_JSON: {
            "server": {
                "auth-server-url":  "https://server/auth/",
                "realm":            "realm_name",
                "resource":         "client_id",
                "credentials": {
                    "secret": "client_secret"
                }
            }
        }
    """

    def get_host_oidc(hostname: str, oidc_config_dict: dict) -> dict:
        for key, config in oidc_config_dict.items():
            if key in str(hostname) or hostname == key:
                log.debug(f"get_host_oidc: Found OIDC adapter for '{hostname}'")
                return config
        return None

    if not isinstance(host, str):
        raise OIDCConfigException(f"Cannot determine OIDC config. Missing 'host'")

    if not isinstance(api_settings.KEYCLOAK_MULTI_OIDC_JSON, dict):
        raise OIDCConfigException(f"OIDC config KEYCLOAK_MULTI_OIDC_JSON not available")

    oidc_config = get_host_oidc(
        host,
        api_settings.KEYCLOAK_MULTI_OIDC_JSON
    )

    if oidc_config is None:
        raise OIDCConfigException(f"Could not determine OIDC config for "
                                  f"'{str(host)}'")

    return oidc_config


def get_keycloak_openid(host: str = None) -> KeycloakOpenID:
    """ 
        Create a KeycloakOpenID instance from application credentials.
        :param host: If request host is provided will attempt to set application credentials 
                        based on a predefined host list.
                            KEYCLOAK_MULTI_OIDC_JSON

                        otherwise it will fallback to the default configured application credentials
                            KEYCLOAK_SERVER_URL, 
                            KEYCLOAK_REALM, 
                            KEYCLOAK_CLIENT_ID, 
                            KEYCLOAK_CLIENT_SECRET_KEY

        :returns: KeycloakOpenID
    """
    try:
        oidc_config = None
        if isinstance(host, str):
            oidc_config = get_request_oidc_config(host)

        if oidc_config:
            log.debug(
                'get_keycloak_openid: '
                f'OIDC realm={oidc_config["realm"]}'
            )
            return KeycloakOpenID(
                server_url=oidc_config["auth-server-url"],
                realm_name=oidc_config["realm"],
                client_id=oidc_config["resource"],
                client_secret_key=oidc_config["credentials"]["secret"]
            )

        return KeycloakOpenID(
            server_url=api_settings.KEYCLOAK_SERVER_URL,
            realm_name=api_settings.KEYCLOAK_REALM,
            client_id=api_settings.KEYCLOAK_CLIENT_ID,
            client_secret_key=api_settings.KEYCLOAK_CLIENT_SECRET_KEY
        )

    except KeyError as e:
        raise KeyError(
            f'invalid settings: {e}'
        ) from e


def get_resource_roles(decoded_token: Dict, client_id=None) -> List[str]:
    """ Get roles from access token """
    resource_access_roles = []
    try:
        if client_id is None:
            client_id = api_settings.KEYCLOAK_CLIENT_ID

        log.debug(f'{__name__} - get_resource_roles - client_id: {client_id}')

        resource_access_roles = (
            decoded_token
            .get('resource_access', {})
            .get(client_id, {})
            .get('roles', [])
        )
        roles = add_roles_prefix(resource_access_roles)
        log.debug(f'{__name__} - get_resource_roles - roles: {roles}')

        return roles

    except Exception as e:
        log.warning(f'{__name__} - get_resource_roles - Exception: ({str(type(e).__name__ )}) {e}\n'
                    f'{traceback.format_exc()}')
        return []


def add_roles_prefix(roles: List[str]) -> List[str]:
    """ add role prefix configured by KEYCLOAK_ROLE_SET_PREFIX to a list of roles """
    log.debug(f'{__name__} - get_resource_roles - roles: {roles}')
    prefixed_roles = [prefix_role(x) for x in roles]
    log.debug(
        f'{__name__} - get_resource_roles - prefixed_roles: {prefixed_roles}'
    )
    return prefixed_roles


def prefix_role(role: str) -> str:
    """ add prefix to role string """
    role_prefix = (
        api_settings.KEYCLOAK_ROLE_SET_PREFIX
        if api_settings.KEYCLOAK_ROLE_SET_PREFIX
        and isinstance(api_settings.KEYCLOAK_ROLE_SET_PREFIX, str)
        else ''
    )
    return f'{role_prefix}{role}'
