import os
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from keycloak import KeycloakOpenID
import logging

log = logging.getLogger('BackendRequestClient')

class BackendRequestClientException(Exception):
    pass

class BackendRequestClient:
    """ Backend OAuth2 client for use with client credentials. """

    def __init__(self, keycloak_openid: KeycloakOpenID):
        """ 
            :param keycloak_openid: KeycloakOpenID
        """
        if not keycloak_openid:
            raise BackendRequestClientException("KeycloakOpenID not provided")

        self.keycloak_openid = keycloak_openid
        self.token_endpoint = self.get_token_url(
            keycloak_openid.connection.base_url,
            keycloak_openid.realm_name
        )
        self.client = BackendApplicationClient(client_id=keycloak_openid.client_id)
        self.session = OAuth2Session(client=self.client)

    def get_token_url(self, host: str, realm_name: str) -> str:
        """ OAuth token endpoint 
            :param host: Auth provider host
            :param realm_name: Realm name
            :returns: Token URL
        """
        return os.path.join(f"{host}",
                            f"realms",
                            f"{realm_name}",
                            f"protocol/openid-connect/token")

    def fetch_token(self) -> dict:
        log.info(f"fetch_token: {self.token_endpoint}")
        return self.session.fetch_token(
            token_url=self.token_endpoint,
            client_id=self.keycloak_openid.client_id,
            client_secret=self.keycloak_openid.client_secret_key
        )

    def get(self, url):
        """ GET request method """
        self.fetch_token()
        return self.session.get(url)

    def post(self, url, json):
        """ POST request method """
        self.fetch_token()
        return self.session.post(url, json=json)