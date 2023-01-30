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
    'GetFirewallFilteringSourceIPGroupsResult',
    'AwaitableGetFirewallFilteringSourceIPGroupsResult',
    'get_firewall_filtering_source_ip_groups',
    'get_firewall_filtering_source_ip_groups_output',
]

@pulumi.output_type
class GetFirewallFilteringSourceIPGroupsResult:
    """
    A collection of values returned by getFirewallFilteringSourceIPGroups.
    """
    def __init__(__self__, description=None, id=None, ip_addresses=None, name=None):
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if id and not isinstance(id, int):
            raise TypeError("Expected argument 'id' to be a int")
        pulumi.set(__self__, "id", id)
        if ip_addresses and not isinstance(ip_addresses, list):
            raise TypeError("Expected argument 'ip_addresses' to be a list")
        pulumi.set(__self__, "ip_addresses", ip_addresses)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        (String)
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The ID of this resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipAddresses")
    def ip_addresses(self) -> Sequence[str]:
        """
        (List of String)
        """
        return pulumi.get(self, "ip_addresses")

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")


class AwaitableGetFirewallFilteringSourceIPGroupsResult(GetFirewallFilteringSourceIPGroupsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFirewallFilteringSourceIPGroupsResult(
            description=self.description,
            id=self.id,
            ip_addresses=self.ip_addresses,
            name=self.name)


def get_firewall_filtering_source_ip_groups(id: Optional[int] = None,
                                            name: Optional[str] = None,
                                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFirewallFilteringSourceIPGroupsResult:
    """
    Use the **zia_firewall_filtering_ip_source_groups** data source to get information about ip source groups available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.Firewall.get_firewall_filtering_source_ip_groups(name="example")
    ```


    :param int id: The ID of the ip source group resource.
    :param str name: The name of the ip source group to be exported.
    """
    __args__ = dict()
    __args__['id'] = id
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:Firewall/getFirewallFilteringSourceIPGroups:getFirewallFilteringSourceIPGroups', __args__, opts=opts, typ=GetFirewallFilteringSourceIPGroupsResult).value

    return AwaitableGetFirewallFilteringSourceIPGroupsResult(
        description=__ret__.description,
        id=__ret__.id,
        ip_addresses=__ret__.ip_addresses,
        name=__ret__.name)


@_utilities.lift_output_func(get_firewall_filtering_source_ip_groups)
def get_firewall_filtering_source_ip_groups_output(id: Optional[pulumi.Input[Optional[int]]] = None,
                                                   name: Optional[pulumi.Input[Optional[str]]] = None,
                                                   opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetFirewallFilteringSourceIPGroupsResult]:
    """
    Use the **zia_firewall_filtering_ip_source_groups** data source to get information about ip source groups available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.Firewall.get_firewall_filtering_source_ip_groups(name="example")
    ```


    :param int id: The ID of the ip source group resource.
    :param str name: The name of the ip source group to be exported.
    """
    ...