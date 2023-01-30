# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'LocationManagementVpnCredential',
    'GetLocationManagementVpnCredentialResult',
    'GetLocationManagementVpnCredentialLocationResult',
    'GetLocationManagementVpnCredentialManagedByResult',
]

@pulumi.output_type
class LocationManagementVpnCredential(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "ipAddress":
            suggest = "ip_address"
        elif key == "preSharedKey":
            suggest = "pre_shared_key"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in LocationManagementVpnCredential. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        LocationManagementVpnCredential.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        LocationManagementVpnCredential.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 comments: Optional[str] = None,
                 fqdn: Optional[str] = None,
                 id: Optional[int] = None,
                 ip_address: Optional[str] = None,
                 pre_shared_key: Optional[str] = None,
                 type: Optional[str] = None):
        """
        :param int id: VPN credential resource id. The value is required if `ip_addresses` are not defined.
        """
        if comments is not None:
            pulumi.set(__self__, "comments", comments)
        if fqdn is not None:
            pulumi.set(__self__, "fqdn", fqdn)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if ip_address is not None:
            pulumi.set(__self__, "ip_address", ip_address)
        if pre_shared_key is not None:
            pulumi.set(__self__, "pre_shared_key", pre_shared_key)
        if type is not None:
            pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter
    def comments(self) -> Optional[str]:
        return pulumi.get(self, "comments")

    @property
    @pulumi.getter
    def fqdn(self) -> Optional[str]:
        return pulumi.get(self, "fqdn")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        """
        VPN credential resource id. The value is required if `ip_addresses` are not defined.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipAddress")
    def ip_address(self) -> Optional[str]:
        return pulumi.get(self, "ip_address")

    @property
    @pulumi.getter(name="preSharedKey")
    def pre_shared_key(self) -> Optional[str]:
        return pulumi.get(self, "pre_shared_key")

    @property
    @pulumi.getter
    def type(self) -> Optional[str]:
        return pulumi.get(self, "type")


@pulumi.output_type
class GetLocationManagementVpnCredentialResult(dict):
    def __init__(__self__, *,
                 comments: str,
                 fqdn: str,
                 id: int,
                 locations: Sequence['outputs.GetLocationManagementVpnCredentialLocationResult'],
                 managed_bies: Sequence['outputs.GetLocationManagementVpnCredentialManagedByResult'],
                 pre_shared_key: str,
                 type: str):
        """
        :param str comments: (String) Additional information about this VPN credential.
               Additional information about this VPN credential.
        :param str fqdn: (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        :param int id: The ID of the location to be exported.
        :param Sequence['GetLocationManagementVpnCredentialLocationArgs'] locations: (List of Object)
        :param Sequence['GetLocationManagementVpnCredentialManagedByArgs'] managed_bies: (List of Object)
        :param str pre_shared_key: (String) Pre-shared key. This is a required field for `UFQDN` and IP auth type.
        :param str type: (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        """
        pulumi.set(__self__, "comments", comments)
        pulumi.set(__self__, "fqdn", fqdn)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "locations", locations)
        pulumi.set(__self__, "managed_bies", managed_bies)
        pulumi.set(__self__, "pre_shared_key", pre_shared_key)
        pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter
    def comments(self) -> str:
        """
        (String) Additional information about this VPN credential.
        Additional information about this VPN credential.
        """
        return pulumi.get(self, "comments")

    @property
    @pulumi.getter
    def fqdn(self) -> str:
        """
        (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        """
        return pulumi.get(self, "fqdn")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of the location to be exported.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def locations(self) -> Sequence['outputs.GetLocationManagementVpnCredentialLocationResult']:
        """
        (List of Object)
        """
        return pulumi.get(self, "locations")

    @property
    @pulumi.getter(name="managedBies")
    def managed_bies(self) -> Sequence['outputs.GetLocationManagementVpnCredentialManagedByResult']:
        """
        (List of Object)
        """
        return pulumi.get(self, "managed_bies")

    @property
    @pulumi.getter(name="preSharedKey")
    def pre_shared_key(self) -> str:
        """
        (String) Pre-shared key. This is a required field for `UFQDN` and IP auth type.
        """
        return pulumi.get(self, "pre_shared_key")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        """
        return pulumi.get(self, "type")


@pulumi.output_type
class GetLocationManagementVpnCredentialLocationResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param Mapping[str, str] extensions: (Map of String)
        :param int id: The ID of the location to be exported.
        :param str name: The name of the location to be exported.
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        """
        (Map of String)
        """
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of the location to be exported.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the location to be exported.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetLocationManagementVpnCredentialManagedByResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param Mapping[str, str] extensions: (Map of String)
        :param int id: The ID of the location to be exported.
        :param str name: The name of the location to be exported.
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        """
        (Map of String)
        """
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of the location to be exported.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the location to be exported.
        """
        return pulumi.get(self, "name")


