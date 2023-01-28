# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities

__all__ = [
    'GetZIAFirewallFilteringApplicationResult',
    'AwaitableGetZIAFirewallFilteringApplicationResult',
    'get_zia_firewall_filtering_application',
    'get_zia_firewall_filtering_application_output',
]

@pulumi.output_type
class GetZIAFirewallFilteringApplicationResult:
    """
    A collection of values returned by getZIAFirewallFilteringApplication.
    """
    def __init__(__self__, deprecated=None, description=None, id=None, locale=None, parent_category=None):
        if deprecated and not isinstance(deprecated, bool):
            raise TypeError("Expected argument 'deprecated' to be a bool")
        pulumi.set(__self__, "deprecated", deprecated)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if locale and not isinstance(locale, str):
            raise TypeError("Expected argument 'locale' to be a str")
        pulumi.set(__self__, "locale", locale)
        if parent_category and not isinstance(parent_category, str):
            raise TypeError("Expected argument 'parent_category' to be a str")
        pulumi.set(__self__, "parent_category", parent_category)

    @property
    @pulumi.getter
    def deprecated(self) -> bool:
        """
        (Boolean)
        """
        return pulumi.get(self, "deprecated")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        (String)
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def locale(self) -> Optional[str]:
        return pulumi.get(self, "locale")

    @property
    @pulumi.getter(name="parentCategory")
    def parent_category(self) -> str:
        """
        (String)
        """
        return pulumi.get(self, "parent_category")


class AwaitableGetZIAFirewallFilteringApplicationResult(GetZIAFirewallFilteringApplicationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIAFirewallFilteringApplicationResult(
            deprecated=self.deprecated,
            description=self.description,
            id=self.id,
            locale=self.locale,
            parent_category=self.parent_category)


def get_zia_firewall_filtering_application(id: Optional[str] = None,
                                           locale: Optional[str] = None,
                                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIAFirewallFilteringApplicationResult:
    """
    Use the **zia_firewall_filtering_network_application** data source to get information about a network application available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network application rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    apns = zia.get_zia_firewall_filtering_application(id="APNS",
        locale="en-US")
    ```

    ```python
    import pulumi
    import pulumi_zia as zia

    dict = zia.get_zia_firewall_filtering_application(id="DICT")
    ```


    :param str id: The name of the ip source group to be exported.
    """
    __args__ = dict()
    __args__['id'] = id
    __args__['locale'] = locale
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIAFirewallFilteringApplication:getZIAFirewallFilteringApplication', __args__, opts=opts, typ=GetZIAFirewallFilteringApplicationResult).value

    return AwaitableGetZIAFirewallFilteringApplicationResult(
        deprecated=__ret__.deprecated,
        description=__ret__.description,
        id=__ret__.id,
        locale=__ret__.locale,
        parent_category=__ret__.parent_category)


@_utilities.lift_output_func(get_zia_firewall_filtering_application)
def get_zia_firewall_filtering_application_output(id: Optional[pulumi.Input[Optional[str]]] = None,
                                                  locale: Optional[pulumi.Input[Optional[str]]] = None,
                                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetZIAFirewallFilteringApplicationResult]:
    """
    Use the **zia_firewall_filtering_network_application** data source to get information about a network application available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network application rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    apns = zia.get_zia_firewall_filtering_application(id="APNS",
        locale="en-US")
    ```

    ```python
    import pulumi
    import pulumi_zia as zia

    dict = zia.get_zia_firewall_filtering_application(id="DICT")
    ```


    :param str id: The name of the ip source group to be exported.
    """
    ...
