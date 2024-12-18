import logging
from typing import List

from rest_framework import permissions

from . import __title__
from .keycloak import prefix_role

log = logging.getLogger(__title__)

ROLE_GUEST = prefix_role('guest')
ROLE_USER = prefix_role('user')
ROLE_SERVICE = prefix_role('service')
ROLE_ADMIN = prefix_role('admin')


def _has_required_group(request, required_groups: List[str]) -> bool:
    user_groups = [x.name for x in request.user.groups.all()]
    log.info(
        '_has_required_group | required_groups: '
        f'{required_groups}'
    )
    log.info(
        '_has_required_group | user_groups: '
        f'{user_groups}'
    )
    return bool(
        set(required_groups)
        .intersection(
            set([x.name for x in request.user.groups.all()])
        )
    )


class BaseGroupBasedPermission(permissions.BasePermission):
    required_groups = []

    def has_permission(self, request, view):
        log.info(
            'BaseGroupBasedPermission.has_permission: '
            f'{self.required_groups}'
        )
        return bool(
            request.user and _has_required_group(request, self.required_groups)
        )

    def has_object_permission(self, request, view, obj):
        log.info('BaseGroupBasedPermission.has_object_permission')
        return self.has_permission(request, view)


class HasAdminGroup(BaseGroupBasedPermission):
    required_groups = [ROLE_ADMIN]


class HasUserGroup(BaseGroupBasedPermission):
    required_groups = [ROLE_USER]


class HasServiceGroup(BaseGroupBasedPermission):
    required_groups = [ROLE_SERVICE]


class HasOwnerGroup(permissions.BasePermission):
    """ validate auth user is obj.owner """

    def has_object_permission(self, request, view, obj):
        required_groups = [str(obj.owner.pk)]
        log.info(
            'HasOwnerGroup.has_object_permission: '
            f'{required_groups}'
        )
        return bool(
            request.user and _has_required_group(request, required_groups)
        )


def _has_required_role(request, required_roles: List[str]) -> bool:
    log.info(
        '_has_required_role | required_roles: '
        f'{required_roles}'
    )
    roles = getattr(request, 'roles', [])
    log.info(
        '_has_required_role | request.roles: '
        f'{roles}'
    )
    return bool(set(required_roles).intersection(set(roles)))


class BaseRoleBasedPermission(permissions.BasePermission):
    required_roles = []

    def has_permission(self, request, view):
        log.info(
            'BaseRoleBasedPermission.has_permission: '
            f'{self.required_roles}'
        )
        return bool(
            request.user and _has_required_role(request, self.required_roles)
        )

    def has_object_permission(self, request, view, obj):
        log.info('BaseRoleBasedPermission.has_object_permission')
        return self.has_permission(request, view)


class HasAdminRole(BaseRoleBasedPermission):
    required_roles = [ROLE_ADMIN]


class HasUserRole(BaseRoleBasedPermission):
    required_roles = [ROLE_USER]


class HasServiceRole(BaseRoleBasedPermission):
    required_roles = [ROLE_SERVICE]


class HasOwnerRole(permissions.BasePermission):
    """ validate auth user is obj.owner """

    def has_object_permission(self, request, view, obj):
        required_roles = [str(obj.owner.pk)]
        log.info(
            'HasOwnerRole.has_object_permission: '
            f'{required_roles}'
        )
        return bool(
            request.user and _has_required_role(request, required_roles)
        )
