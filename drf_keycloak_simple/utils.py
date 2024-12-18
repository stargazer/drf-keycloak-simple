import logging
import jwt
from urllib.parse import urlparse

from django.http.request import validate_host
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings


logger = logging.getLogger(__name__)


def get_token_issuer(key: str):
    """
    Decode an unverified token to get the issuer and validate it against ALLOWED_HOSTS
    :param key: token string
    :return: issuer
    :raises: AuthenticationFailed
    """
    decoded = jwt.decode(key, options={"verify_signature": False})
    if not isinstance(decoded, dict):
        logger.warning("Unable to get token issuer. Could not decode token")
        return None

    issuer_host = urlparse(decoded.get('iss')).netloc

    # Ensure issuer is in ALLOWED_HOSTS
    if validate_host(issuer_host, api_settings.ALLOWED_HOSTS):
        return issuer_host

    raise AuthenticationFailed(f"Token issuer ({str(issuer_host)}) is not in DJANGO_ALLOWED_HOSTS")