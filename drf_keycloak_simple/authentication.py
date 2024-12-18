import logging
import re
from typing import Tuple, Dict, List

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, update_last_login, Group
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from .keycloak import (
    OIDCConfigException,
    get_keycloak_openid,
    get_resource_roles,
    add_roles_prefix
)
from .settings import api_settings
from .utils import get_token_issuer


logger = logging.getLogger(__name__)
User = get_user_model()


class KeycloakAuthentication(authentication.TokenAuthentication):
    keyword = api_settings.KEYCLOAK_AUTH_HEADER_PREFIX

    keycloak_openid = None

    def authenticate(self, request):
        credentials = super().authenticate(request)
        if credentials:
            user, decoded_token = credentials

            # Append realm_name
            decoded_token.update(
                {'realm_name': self.keycloak_openid.realm_name}
            )

            # Expose Keycloak roles
            request.roles = self._get_roles(user, decoded_token)

            # Expose keycloak_openid
            request.keycloak_openid = self.keycloak_openid

            # Create local application groups?
            if api_settings.KEYCLOAK_MANAGE_LOCAL_GROUPS is True:
                groups = self._get_or_create_groups(request.roles)
                user.groups.set(groups)

            # Set user is_staff based on Keycloak role mapping
            self._user_toggle_is_staff(request, user)

        return credentials

    def authenticate_credentials(
        self,
        key: str
    ) -> Tuple[AnonymousUser, Dict]:
        """ Attempt to verify JWT from Authorization header with Keycloak """
        logger.debug('KeycloakAuthentication.authenticate_credentials')
        try:
            # Create a default KeycloakOpenID configuration if not already available
            if self.keycloak_openid is None:
                self.keycloak_openid = get_keycloak_openid()

            user = None
            # Checks token is active
            decoded_token = self._get_decoded_token(key)
            self._verify_token_active(decoded_token)
            if api_settings.KEYCLOAK_MANAGE_LOCAL_USER is not True:
                logger.debug(
                    'KeycloakAuthentication.authenticate_credentials: '
                    f'{decoded_token}'
                )
                user = AnonymousUser()
            else:
                user = self._handle_local_user(decoded_token)

            logger.debug(
                'KeycloakAuthentication.authenticate_credentials:\n'
                '################# decoded_token ###############\n'
                f'{user} | {decoded_token}\n'
                '################ /decoded_token ###############'
            )

            return (user, decoded_token)
        except Exception as e:
            logger.error(
                'KeycloakAuthentication.authenticate_credentials | '
                f'Exception: {e}'
            )
            raise AuthenticationFailed() from e

    def _get_decoded_token(self, token: str) -> dict:
        return self.keycloak_openid.introspect(token)

    def _verify_token_active(self, decoded_token: dict) -> None:
        """ raises if not active """
        is_active = decoded_token.get('active', False)
        if not is_active:
            raise AuthenticationFailed(
                'Invalid or expired token'
            )

    def _map_keycloak_to_django_fields(self, decoded_token: dict) -> dict:
        """ Map Keycloak access_token fields to Django User attributes """
        django_fields = {}
        kc_username_field = \
            api_settings.KEYCLOAK_FIELD_AS_DJANGO_USERNAME

        if (
            kc_username_field
            and
            isinstance(kc_username_field, str)
        ):
            django_fields['username'] = decoded_token.get(kc_username_field, '')

        django_fields['email'] = decoded_token.get('email', '')

        # django stores first_name and last_name as empty strings
        # by default, not None
        django_fields['first_name'] = \
            decoded_token.get('given_name', '')
        django_fields['last_name'] = \
            decoded_token.get('family_name', '')

        return django_fields

    def _update_user(self, user: User, django_fields: dict) -> User:
        """ if user exists, keep data updated as necessary """
        save_model = False

        for key, value in django_fields.items():
            try:
                if getattr(user, key) != value:
                    setattr(user, key, value)
                    save_model = True
            except Exception:
                logger.warning(
                    'KeycloakAuthentication.'
                    '_update_user | '
                    f'setattr: {key} field does not exist'
                )
        if save_model:
            user.save()
        return user

    def _handle_local_user(self, decoded_token: dict) -> User:
        """ used to update/create local users from keycloak data """
        django_uuid_field = \
            api_settings.KEYCLOAK_DJANGO_USER_UUID_FIELD

        sub = decoded_token['sub']
        django_fields = self._map_keycloak_to_django_fields(decoded_token)

        user = None
        try:
            user = User.objects.get(**{django_uuid_field: sub})
            user = self._update_user(user, django_fields)

        except ObjectDoesNotExist:
            logger.warning(
                'KeycloakAuthentication._handle_local_user | '
                f'ObjectDoesNotExist: {sub} does not exist - creating'
            )

        if user is None:
            # Add uuid field and create
            django_fields.update(**{django_uuid_field: sub})
            user = User.objects.create_user(**django_fields)

        update_last_login(sender=None, user=user)
        return user

    def _get_roles(
        self,
        user: User,
        decoded_token: dict
    ) -> List[str]:
        """ try to add roles from authenticated keycloak user """
        roles = []
        try:
            roles += get_resource_roles(
                decoded_token,
                self.keycloak_openid.client_id
            )
            roles.append(str(user.pk))
        except Exception as e:
            logger.warning(
                'KeycloakAuthentication._get_roles | '
                f'Exception: {e}'
            )

        logger.debug(f'KeycloakAuthentication._get_roles: {roles}')
        return roles

    def _get_or_create_groups(self, roles: List[str]) -> List[Group]:
        groups = []
        for role in roles:
            group, created = Group.objects.get_or_create(name=role)
            if created:
                logger.debug(
                    'KeycloakAuthentication._get_or_create_groups | created: '
                    f'{group.name}'
                )
            else:
                logger.debug(
                    'KeycloakAuthentication._get_or_create_groups | exists: '
                    f'{group.name}'
                )
            groups.append(group)
        return groups

    def _user_toggle_is_staff(self, request, user: User) -> None:
        """
        toggle user.is_staff if a role mapping has been declared in settings
        """
        try:
            # catch None or django.contrib.auth.models.AnonymousUser
            valid_user = bool(
                user
                and isinstance(user, User)
                and hasattr(user, 'is_staff')
                and getattr(user, 'is_superuser', False) is False
            )
            logger.debug(
                f'KeycloakAuthentication._user_toggle_is_staff | {user} | '
                f'valid_user: {valid_user}'
            )
            if (
                valid_user
                and api_settings.KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF
                and type(api_settings.KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF)
                in [list, tuple, set]
            ):
                is_staff_roles = set(
                    add_roles_prefix(
                        api_settings.KEYCLOAK_ROLES_TO_DJANGO_IS_STAFF
                    )
                )
                logger.debug(
                    f'KeycloakAuthentication._user_toggle_is_staff | {user} | '
                    f'is_staff_roles: {is_staff_roles}'
                )
                user_roles = set(request.roles)
                logger.debug(
                    f'KeycloakAuthentication._user_toggle_is_staff | {user} | '
                    f'user_roles: {user_roles}'
                )
                is_staff = bool(is_staff_roles.intersection(user_roles))
                logger.debug(
                    f'KeycloakAuthentication._user_toggle_is_staff | {user} | '
                    f'is_staff: {is_staff}'
                )
                # don't write unnecessarily, check different first
                if is_staff != user.is_staff:
                    user.is_staff = is_staff
                    user.save()

        except Exception as e:
            logger.warning(
                'KeycloakAuthentication._user_toggle_is_staff | '
                f'Exception: {e}'
            )