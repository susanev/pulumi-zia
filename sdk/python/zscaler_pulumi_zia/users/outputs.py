# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'UserManagementDepartment',
    'UserManagementGroups',
    'GetUserManagementDepartmentResult',
    'GetUserManagementGroupResult',
]

@pulumi.output_type
class UserManagementDepartment(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "idpId":
            suggest = "idp_id"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in UserManagementDepartment. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        UserManagementDepartment.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        UserManagementDepartment.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 comments: Optional[str] = None,
                 deleted: Optional[bool] = None,
                 id: Optional[int] = None,
                 idp_id: Optional[int] = None,
                 name: Optional[str] = None):
        """
        :param int id: Department ID
        :param str name: User name. This appears when choosing users for policies.
        """
        if comments is not None:
            pulumi.set(__self__, "comments", comments)
        if deleted is not None:
            pulumi.set(__self__, "deleted", deleted)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if idp_id is not None:
            pulumi.set(__self__, "idp_id", idp_id)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def comments(self) -> Optional[str]:
        return pulumi.get(self, "comments")

    @property
    @pulumi.getter
    def deleted(self) -> Optional[bool]:
        return pulumi.get(self, "deleted")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        """
        Department ID
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idpId")
    def idp_id(self) -> Optional[int]:
        return pulumi.get(self, "idp_id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        User name. This appears when choosing users for policies.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class UserManagementGroups(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Department ID
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Department ID
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class GetUserManagementDepartmentResult(dict):
    def __init__(__self__, *,
                 comments: str,
                 deleted: bool,
                 id: int,
                 idp_id: int,
                 name: str):
        """
        :param str comments: (String) Additional information about the group
        :param bool deleted: (Boolean) default: `false`
        :param int id: The ID of the time window resource.
        :param int idp_id: (Number) Unique identfier for the identity provider (IdP)
        :param str name: User name. This appears when choosing users for policies.
        """
        pulumi.set(__self__, "comments", comments)
        pulumi.set(__self__, "deleted", deleted)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idp_id", idp_id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def comments(self) -> str:
        """
        (String) Additional information about the group
        """
        return pulumi.get(self, "comments")

    @property
    @pulumi.getter
    def deleted(self) -> bool:
        """
        (Boolean) default: `false`
        """
        return pulumi.get(self, "deleted")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of the time window resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idpId")
    def idp_id(self) -> int:
        """
        (Number) Unique identfier for the identity provider (IdP)
        """
        return pulumi.get(self, "idp_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        User name. This appears when choosing users for policies.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetUserManagementGroupResult(dict):
    def __init__(__self__, *,
                 comments: str,
                 id: int,
                 idp_id: int,
                 name: str):
        """
        :param str comments: (String) Additional information about the group
        :param int id: The ID of the time window resource.
        :param int idp_id: (Number) Unique identfier for the identity provider (IdP)
        :param str name: User name. This appears when choosing users for policies.
        """
        pulumi.set(__self__, "comments", comments)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idp_id", idp_id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def comments(self) -> str:
        """
        (String) Additional information about the group
        """
        return pulumi.get(self, "comments")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of the time window resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idpId")
    def idp_id(self) -> int:
        """
        (Number) Unique identfier for the identity provider (IdP)
        """
        return pulumi.get(self, "idp_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        User name. This appears when choosing users for policies.
        """
        return pulumi.get(self, "name")


