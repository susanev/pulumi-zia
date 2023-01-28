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
    'GetZIAAuthSettingsURLsResult',
    'AwaitableGetZIAAuthSettingsURLsResult',
    'get_zia_auth_settings_urls',
]

@pulumi.output_type
class GetZIAAuthSettingsURLsResult:
    """
    A collection of values returned by getZIAAuthSettingsURLs.
    """
    def __init__(__self__, id=None, urls=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if urls and not isinstance(urls, list):
            raise TypeError("Expected argument 'urls' to be a list")
        pulumi.set(__self__, "urls", urls)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def urls(self) -> Sequence[str]:
        return pulumi.get(self, "urls")


class AwaitableGetZIAAuthSettingsURLsResult(GetZIAAuthSettingsURLsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIAAuthSettingsURLsResult(
            id=self.id,
            urls=self.urls)


def get_zia_auth_settings_urls(opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIAAuthSettingsURLsResult:
    """
    Use the **zia_auth_settings_urls** data source to get a list of URLs that were exempted from cookie authentiation and SSL Inspection in the Zscaler Internet Access cloud or via the API. To learn more see [URL Format Guidelines](https://help.zscaler.com/zia/url-format-guidelines)

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    foo = zia.get_zia_auth_settings_urls()
    ```
    """
    __args__ = dict()
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIAAuthSettingsURLs:getZIAAuthSettingsURLs', __args__, opts=opts, typ=GetZIAAuthSettingsURLsResult).value

    return AwaitableGetZIAAuthSettingsURLsResult(
        id=__ret__.id,
        urls=__ret__.urls)