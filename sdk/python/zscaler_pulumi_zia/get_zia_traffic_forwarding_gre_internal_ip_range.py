# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs

__all__ = [
    'GetZIATrafficForwardingGREInternalIPRangeResult',
    'AwaitableGetZIATrafficForwardingGREInternalIPRangeResult',
    'get_zia_traffic_forwarding_gre_internal_ip_range',
    'get_zia_traffic_forwarding_gre_internal_ip_range_output',
]

@pulumi.output_type
class GetZIATrafficForwardingGREInternalIPRangeResult:
    """
    A collection of values returned by getZIATrafficForwardingGREInternalIPRange.
    """
    def __init__(__self__, id=None, lists=None, required_count=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lists and not isinstance(lists, list):
            raise TypeError("Expected argument 'lists' to be a list")
        pulumi.set(__self__, "lists", lists)
        if required_count and not isinstance(required_count, int):
            raise TypeError("Expected argument 'required_count' to be a int")
        pulumi.set(__self__, "required_count", required_count)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def lists(self) -> Sequence['outputs.GetZIATrafficForwardingGREInternalIPRangeListResult']:
        return pulumi.get(self, "lists")

    @property
    @pulumi.getter(name="requiredCount")
    def required_count(self) -> Optional[int]:
        return pulumi.get(self, "required_count")


class AwaitableGetZIATrafficForwardingGREInternalIPRangeResult(GetZIATrafficForwardingGREInternalIPRangeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIATrafficForwardingGREInternalIPRangeResult(
            id=self.id,
            lists=self.lists,
            required_count=self.required_count)


def get_zia_traffic_forwarding_gre_internal_ip_range(required_count: Optional[int] = None,
                                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIATrafficForwardingGREInternalIPRangeResult:
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()
    __args__['requiredCount'] = required_count
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIATrafficForwardingGREInternalIPRange:getZIATrafficForwardingGREInternalIPRange', __args__, opts=opts, typ=GetZIATrafficForwardingGREInternalIPRangeResult).value

    return AwaitableGetZIATrafficForwardingGREInternalIPRangeResult(
        id=__ret__.id,
        lists=__ret__.lists,
        required_count=__ret__.required_count)


@_utilities.lift_output_func(get_zia_traffic_forwarding_gre_internal_ip_range)
def get_zia_traffic_forwarding_gre_internal_ip_range_output(required_count: Optional[pulumi.Input[Optional[int]]] = None,
                                                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetZIATrafficForwardingGREInternalIPRangeResult]:
    """
    Use this data source to access information about an existing resource.
    """
    ...
