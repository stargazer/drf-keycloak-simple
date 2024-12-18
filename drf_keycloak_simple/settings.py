""" Settings config for the drf_keycloak_auth application """
import datetime
import os

from django.conf import settings
from rest_framework.settings import APISettings

import json

USER_SETTINGS = getattr(settings, 'DRF_KEYCLOAK_AUTH', None)

# should be comma separated string
KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF = \
    os.getenv('KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF')

DEFAULTS = {
    'ALLOWED_HOSTS': os.getenv('DJANGO_ALLOWED_HOSTS', '').split(' '),

    'KEYCLOAK_MULTI_OIDC_JSON': (
        json.loads(os.getenv('KEYCLOAK_MULTI_OIDC_JSON'))
        if os.getenv('KEYCLOAK_MULTI_OIDC_JSON')
        else None
    ),
    
    'KEYCLOAK_SERVER_URL': os.getenv('KEYCLOAK_SERVER_URL'),

    'KEYCLOAK_REALM': os.getenv('KEYCLOAK_REALM'),

    'KEYCLOAK_CLIENT_ID': os.getenv('KEYCLOAK_CLIENT_ID'),

    'KEYCLOAK_CLIENT_SECRET_KEY': os.getenv('KEYCLOAK_CLIENT_SECRET_KEY'),

    'KEYCLOAK_AUTH_HEADER_PREFIX':
        os.getenv('KEYCLOAK_AUTH_HEADER_PREFIX', 'Bearer'),

    'KEYCLOAK_ROLE_SET_PREFIX':
        os.getenv('KEYCLOAK_ROLE_SET_PREFIX', 'role:'),

    'KEYCLOAK_MANAGE_LOCAL_USER':
        os.getenv('KEYCLOAK_MANAGE_LOCAL_USER', True),

    'KEYCLOAK_MANAGE_LOCAL_GROUPS':
        os.getenv('KEYCLOAK_MANAGE_LOCAL_GROUPS', False),

    'KEYCLOAK_DJANGO_USER_UUID_FIELD':
        os.getenv('KEYCLOAK_DJANGO_USER_UUID_FIELD', 'pk'),

    'KEYCLOAK_FIELD_AS_DJANGO_USERNAME':
        os.getenv('KEYCLOAK_FIELD_AS_DJANGO_USERNAME', 'preferred_username'),

    'KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF': (
        [x.strip() for x in KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF.split(',')]
        if KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF
        else ['admin']  # can be list, tuple or set
    )
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
