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
    'GetZIALocationManagementResult',
    'AwaitableGetZIALocationManagementResult',
    'get_zia_location_management',
    'get_zia_location_management_output',
]

@pulumi.output_type
class GetZIALocationManagementResult:
    """
    A collection of values returned by getZIALocationManagement.
    """
    def __init__(__self__, aup_block_internet_until_accepted=None, aup_enabled=None, aup_force_ssl_inspection=None, aup_timeout_in_days=None, auth_required=None, caution_enabled=None, country=None, description=None, display_time_unit=None, dn_bandwidth=None, id=None, idle_time_in_minutes=None, ip_addresses=None, ips_control=None, name=None, ofw_enabled=None, parent_id=None, ports=None, profile=None, ssl_scan_enabled=None, surrogate_ip=None, surrogate_ip_enforced_for_known_browsers=None, surrogate_refresh_time_in_minutes=None, surrogate_refresh_time_unit=None, tz=None, up_bandwidth=None, vpn_credentials=None, xff_forward_enabled=None, zapp_ssl_scan_enabled=None):
        if aup_block_internet_until_accepted and not isinstance(aup_block_internet_until_accepted, bool):
            raise TypeError("Expected argument 'aup_block_internet_until_accepted' to be a bool")
        pulumi.set(__self__, "aup_block_internet_until_accepted", aup_block_internet_until_accepted)
        if aup_enabled and not isinstance(aup_enabled, bool):
            raise TypeError("Expected argument 'aup_enabled' to be a bool")
        pulumi.set(__self__, "aup_enabled", aup_enabled)
        if aup_force_ssl_inspection and not isinstance(aup_force_ssl_inspection, bool):
            raise TypeError("Expected argument 'aup_force_ssl_inspection' to be a bool")
        pulumi.set(__self__, "aup_force_ssl_inspection", aup_force_ssl_inspection)
        if aup_timeout_in_days and not isinstance(aup_timeout_in_days, int):
            raise TypeError("Expected argument 'aup_timeout_in_days' to be a int")
        pulumi.set(__self__, "aup_timeout_in_days", aup_timeout_in_days)
        if auth_required and not isinstance(auth_required, bool):
            raise TypeError("Expected argument 'auth_required' to be a bool")
        pulumi.set(__self__, "auth_required", auth_required)
        if caution_enabled and not isinstance(caution_enabled, bool):
            raise TypeError("Expected argument 'caution_enabled' to be a bool")
        pulumi.set(__self__, "caution_enabled", caution_enabled)
        if country and not isinstance(country, str):
            raise TypeError("Expected argument 'country' to be a str")
        pulumi.set(__self__, "country", country)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_time_unit and not isinstance(display_time_unit, str):
            raise TypeError("Expected argument 'display_time_unit' to be a str")
        pulumi.set(__self__, "display_time_unit", display_time_unit)
        if dn_bandwidth and not isinstance(dn_bandwidth, int):
            raise TypeError("Expected argument 'dn_bandwidth' to be a int")
        pulumi.set(__self__, "dn_bandwidth", dn_bandwidth)
        if id and not isinstance(id, int):
            raise TypeError("Expected argument 'id' to be a int")
        pulumi.set(__self__, "id", id)
        if idle_time_in_minutes and not isinstance(idle_time_in_minutes, int):
            raise TypeError("Expected argument 'idle_time_in_minutes' to be a int")
        pulumi.set(__self__, "idle_time_in_minutes", idle_time_in_minutes)
        if ip_addresses and not isinstance(ip_addresses, list):
            raise TypeError("Expected argument 'ip_addresses' to be a list")
        pulumi.set(__self__, "ip_addresses", ip_addresses)
        if ips_control and not isinstance(ips_control, bool):
            raise TypeError("Expected argument 'ips_control' to be a bool")
        pulumi.set(__self__, "ips_control", ips_control)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if ofw_enabled and not isinstance(ofw_enabled, bool):
            raise TypeError("Expected argument 'ofw_enabled' to be a bool")
        pulumi.set(__self__, "ofw_enabled", ofw_enabled)
        if parent_id and not isinstance(parent_id, int):
            raise TypeError("Expected argument 'parent_id' to be a int")
        pulumi.set(__self__, "parent_id", parent_id)
        if ports and not isinstance(ports, str):
            raise TypeError("Expected argument 'ports' to be a str")
        pulumi.set(__self__, "ports", ports)
        if profile and not isinstance(profile, str):
            raise TypeError("Expected argument 'profile' to be a str")
        pulumi.set(__self__, "profile", profile)
        if ssl_scan_enabled and not isinstance(ssl_scan_enabled, bool):
            raise TypeError("Expected argument 'ssl_scan_enabled' to be a bool")
        pulumi.set(__self__, "ssl_scan_enabled", ssl_scan_enabled)
        if surrogate_ip and not isinstance(surrogate_ip, bool):
            raise TypeError("Expected argument 'surrogate_ip' to be a bool")
        pulumi.set(__self__, "surrogate_ip", surrogate_ip)
        if surrogate_ip_enforced_for_known_browsers and not isinstance(surrogate_ip_enforced_for_known_browsers, bool):
            raise TypeError("Expected argument 'surrogate_ip_enforced_for_known_browsers' to be a bool")
        pulumi.set(__self__, "surrogate_ip_enforced_for_known_browsers", surrogate_ip_enforced_for_known_browsers)
        if surrogate_refresh_time_in_minutes and not isinstance(surrogate_refresh_time_in_minutes, int):
            raise TypeError("Expected argument 'surrogate_refresh_time_in_minutes' to be a int")
        pulumi.set(__self__, "surrogate_refresh_time_in_minutes", surrogate_refresh_time_in_minutes)
        if surrogate_refresh_time_unit and not isinstance(surrogate_refresh_time_unit, str):
            raise TypeError("Expected argument 'surrogate_refresh_time_unit' to be a str")
        pulumi.set(__self__, "surrogate_refresh_time_unit", surrogate_refresh_time_unit)
        if tz and not isinstance(tz, str):
            raise TypeError("Expected argument 'tz' to be a str")
        pulumi.set(__self__, "tz", tz)
        if up_bandwidth and not isinstance(up_bandwidth, int):
            raise TypeError("Expected argument 'up_bandwidth' to be a int")
        pulumi.set(__self__, "up_bandwidth", up_bandwidth)
        if vpn_credentials and not isinstance(vpn_credentials, list):
            raise TypeError("Expected argument 'vpn_credentials' to be a list")
        pulumi.set(__self__, "vpn_credentials", vpn_credentials)
        if xff_forward_enabled and not isinstance(xff_forward_enabled, bool):
            raise TypeError("Expected argument 'xff_forward_enabled' to be a bool")
        pulumi.set(__self__, "xff_forward_enabled", xff_forward_enabled)
        if zapp_ssl_scan_enabled and not isinstance(zapp_ssl_scan_enabled, bool):
            raise TypeError("Expected argument 'zapp_ssl_scan_enabled' to be a bool")
        pulumi.set(__self__, "zapp_ssl_scan_enabled", zapp_ssl_scan_enabled)

    @property
    @pulumi.getter(name="aupBlockInternetUntilAccepted")
    def aup_block_internet_until_accepted(self) -> bool:
        """
        (Boolean) For First Time AUP Behavior, Block Internet Access. When set, all internet access (including non-HTTP traffic) is disabled until the user accepts the AUP.
        """
        return pulumi.get(self, "aup_block_internet_until_accepted")

    @property
    @pulumi.getter(name="aupEnabled")
    def aup_enabled(self) -> bool:
        """
        (Boolean) Enable AUP. When set to true, AUP is enabled for the location.
        """
        return pulumi.get(self, "aup_enabled")

    @property
    @pulumi.getter(name="aupForceSslInspection")
    def aup_force_ssl_inspection(self) -> bool:
        """
        (Boolean) For First Time AUP Behavior, Force SSL Inspection. When set, Zscaler will force SSL Inspection in order to enforce AUP for HTTPS traffic.
        """
        return pulumi.get(self, "aup_force_ssl_inspection")

    @property
    @pulumi.getter(name="aupTimeoutInDays")
    def aup_timeout_in_days(self) -> int:
        """
        (Number) Custom AUP Frequency. Refresh time (in days) to re-validate the AUP.
        """
        return pulumi.get(self, "aup_timeout_in_days")

    @property
    @pulumi.getter(name="authRequired")
    def auth_required(self) -> bool:
        """
        (Boolean) Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled.
        """
        return pulumi.get(self, "auth_required")

    @property
    @pulumi.getter(name="cautionEnabled")
    def caution_enabled(self) -> bool:
        """
        (Boolean) Enable Caution. When set to true, a caution notifcation is enabled for the location.
        """
        return pulumi.get(self, "caution_enabled")

    @property
    @pulumi.getter
    def country(self) -> str:
        """
        (String) Country
        """
        return pulumi.get(self, "country")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        (String) Additional notes or information regarding the location or sub-location. The description cannot exceed 1024 characters.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayTimeUnit")
    def display_time_unit(self) -> str:
        """
        (String) Display Time Unit. The time unit to display for IP Surrogate idle time to disassociation.
        """
        return pulumi.get(self, "display_time_unit")

    @property
    @pulumi.getter(name="dnBandwidth")
    def dn_bandwidth(self) -> int:
        """
        (Number) Download bandwidth in bytes. The value `0` implies no Bandwidth Control enforcement.
        """
        return pulumi.get(self, "dn_bandwidth")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        """
        (Number) Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idleTimeInMinutes")
    def idle_time_in_minutes(self) -> int:
        """
        (Number) Idle Time to Disassociation. The user mapping idle time (in minutes) is required if a Surrogate IP is enabled.
        """
        return pulumi.get(self, "idle_time_in_minutes")

    @property
    @pulumi.getter(name="ipAddresses")
    def ip_addresses(self) -> Sequence[str]:
        """
        (List of String) For locations: IP addresses of the egress points that are provisioned in the Zscaler Cloud. Each entry is a single IP address (e.g., `238.10.33.9`). For sub-locations: Egress, internal, or GRE tunnel IP addresses. Each entry is either a single IP address, CIDR (e.g., `10.10.33.0/24`), or range (e.g., `10.10.33.1-10.10.33.10`)).
        """
        return pulumi.get(self, "ip_addresses")

    @property
    @pulumi.getter(name="ipsControl")
    def ips_control(self) -> bool:
        """
        (Boolean) Enable IPS Control. When set to true, IPS Control is enabled for the location if Firewall is enabled.
        """
        return pulumi.get(self, "ips_control")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        (String) The configured name of the entity
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="ofwEnabled")
    def ofw_enabled(self) -> bool:
        """
        (Boolean) Enable Firewall. When set to true, Firewall is enabled for the location.
        """
        return pulumi.get(self, "ofw_enabled")

    @property
    @pulumi.getter(name="parentId")
    def parent_id(self) -> int:
        """
        (Number) - Parent Location ID. If this ID does not exist or is `0`, it is implied that it is a parent location. Otherwise, it is a sub-location whose parent has this ID. x-applicableTo: `SUB`
        """
        return pulumi.get(self, "parent_id")

    @property
    @pulumi.getter
    def ports(self) -> str:
        """
        (String) IP ports that are associated with the location.
        """
        return pulumi.get(self, "ports")

    @property
    @pulumi.getter
    def profile(self) -> str:
        """
        (String) Profile tag that specifies the location traffic type. If not specified, this tag defaults to `Unassigned`.
        """
        return pulumi.get(self, "profile")

    @property
    @pulumi.getter(name="sslScanEnabled")
    def ssl_scan_enabled(self) -> bool:
        """
        (Boolean) This parameter was deprecated and no longer has an effect on SSL policy. It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future.
        """
        return pulumi.get(self, "ssl_scan_enabled")

    @property
    @pulumi.getter(name="surrogateIp")
    def surrogate_ip(self) -> bool:
        """
        (Boolean) Enable Surrogate IP. When set to true, users are mapped to internal device IP addresses.
        """
        return pulumi.get(self, "surrogate_ip")

    @property
    @pulumi.getter(name="surrogateIpEnforcedForKnownBrowsers")
    def surrogate_ip_enforced_for_known_browsers(self) -> bool:
        """
        (Boolean) Enforce Surrogate IP for Known Browsers. When set to true, IP Surrogate is enforced for all known browsers.
        """
        return pulumi.get(self, "surrogate_ip_enforced_for_known_browsers")

    @property
    @pulumi.getter(name="surrogateRefreshTimeInMinutes")
    def surrogate_refresh_time_in_minutes(self) -> int:
        """
        (Number) Refresh Time for re-validation of Surrogacy. The surrogate refresh time (in minutes) to re-validate the IP surrogates.
        """
        return pulumi.get(self, "surrogate_refresh_time_in_minutes")

    @property
    @pulumi.getter(name="surrogateRefreshTimeUnit")
    def surrogate_refresh_time_unit(self) -> str:
        """
        (String) Display Refresh Time Unit. The time unit to display for refresh time for re-validation of surrogacy.
        """
        return pulumi.get(self, "surrogate_refresh_time_unit")

    @property
    @pulumi.getter
    def tz(self) -> str:
        """
        (String) Timezone of the location. If not specified, it defaults to GMT.
        """
        return pulumi.get(self, "tz")

    @property
    @pulumi.getter(name="upBandwidth")
    def up_bandwidth(self) -> int:
        """
        (Number) Upload bandwidth in bytes. The value `0` implies no Bandwidth Control enforcement.
        """
        return pulumi.get(self, "up_bandwidth")

    @property
    @pulumi.getter(name="vpnCredentials")
    def vpn_credentials(self) -> Sequence['outputs.GetZIALocationManagementVpnCredentialResult']:
        return pulumi.get(self, "vpn_credentials")

    @property
    @pulumi.getter(name="xffForwardEnabled")
    def xff_forward_enabled(self) -> bool:
        """
        (Boolean) Enable XFF Forwarding. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header.
        """
        return pulumi.get(self, "xff_forward_enabled")

    @property
    @pulumi.getter(name="zappSslScanEnabled")
    def zapp_ssl_scan_enabled(self) -> bool:
        """
        (Boolean) This parameter was deprecated and no longer has an effect on SSL policy. It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future.
        """
        return pulumi.get(self, "zapp_ssl_scan_enabled")


class AwaitableGetZIALocationManagementResult(GetZIALocationManagementResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIALocationManagementResult(
            aup_block_internet_until_accepted=self.aup_block_internet_until_accepted,
            aup_enabled=self.aup_enabled,
            aup_force_ssl_inspection=self.aup_force_ssl_inspection,
            aup_timeout_in_days=self.aup_timeout_in_days,
            auth_required=self.auth_required,
            caution_enabled=self.caution_enabled,
            country=self.country,
            description=self.description,
            display_time_unit=self.display_time_unit,
            dn_bandwidth=self.dn_bandwidth,
            id=self.id,
            idle_time_in_minutes=self.idle_time_in_minutes,
            ip_addresses=self.ip_addresses,
            ips_control=self.ips_control,
            name=self.name,
            ofw_enabled=self.ofw_enabled,
            parent_id=self.parent_id,
            ports=self.ports,
            profile=self.profile,
            ssl_scan_enabled=self.ssl_scan_enabled,
            surrogate_ip=self.surrogate_ip,
            surrogate_ip_enforced_for_known_browsers=self.surrogate_ip_enforced_for_known_browsers,
            surrogate_refresh_time_in_minutes=self.surrogate_refresh_time_in_minutes,
            surrogate_refresh_time_unit=self.surrogate_refresh_time_unit,
            tz=self.tz,
            up_bandwidth=self.up_bandwidth,
            vpn_credentials=self.vpn_credentials,
            xff_forward_enabled=self.xff_forward_enabled,
            zapp_ssl_scan_enabled=self.zapp_ssl_scan_enabled)


def get_zia_location_management(id: Optional[int] = None,
                                name: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIALocationManagementResult:
    """
    Use the **zia_location_management** data source to get information about a location resource available in the Zscaler Internet Access Location Management. This resource can then be referenced in multiple other resources, such as URL Filtering Rules, Firewall rules etc.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_zia_location_management(name="San Jose")
    ```


    :param int id: The ID of the location to be exported.
    :param str name: The name of the location to be exported.
    """
    __args__ = dict()
    __args__['id'] = id
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIALocationManagement:getZIALocationManagement', __args__, opts=opts, typ=GetZIALocationManagementResult).value

    return AwaitableGetZIALocationManagementResult(
        aup_block_internet_until_accepted=__ret__.aup_block_internet_until_accepted,
        aup_enabled=__ret__.aup_enabled,
        aup_force_ssl_inspection=__ret__.aup_force_ssl_inspection,
        aup_timeout_in_days=__ret__.aup_timeout_in_days,
        auth_required=__ret__.auth_required,
        caution_enabled=__ret__.caution_enabled,
        country=__ret__.country,
        description=__ret__.description,
        display_time_unit=__ret__.display_time_unit,
        dn_bandwidth=__ret__.dn_bandwidth,
        id=__ret__.id,
        idle_time_in_minutes=__ret__.idle_time_in_minutes,
        ip_addresses=__ret__.ip_addresses,
        ips_control=__ret__.ips_control,
        name=__ret__.name,
        ofw_enabled=__ret__.ofw_enabled,
        parent_id=__ret__.parent_id,
        ports=__ret__.ports,
        profile=__ret__.profile,
        ssl_scan_enabled=__ret__.ssl_scan_enabled,
        surrogate_ip=__ret__.surrogate_ip,
        surrogate_ip_enforced_for_known_browsers=__ret__.surrogate_ip_enforced_for_known_browsers,
        surrogate_refresh_time_in_minutes=__ret__.surrogate_refresh_time_in_minutes,
        surrogate_refresh_time_unit=__ret__.surrogate_refresh_time_unit,
        tz=__ret__.tz,
        up_bandwidth=__ret__.up_bandwidth,
        vpn_credentials=__ret__.vpn_credentials,
        xff_forward_enabled=__ret__.xff_forward_enabled,
        zapp_ssl_scan_enabled=__ret__.zapp_ssl_scan_enabled)


@_utilities.lift_output_func(get_zia_location_management)
def get_zia_location_management_output(id: Optional[pulumi.Input[Optional[int]]] = None,
                                       name: Optional[pulumi.Input[Optional[str]]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetZIALocationManagementResult]:
    """
    Use the **zia_location_management** data source to get information about a location resource available in the Zscaler Internet Access Location Management. This resource can then be referenced in multiple other resources, such as URL Filtering Rules, Firewall rules etc.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_zia_location_management(name="San Jose")
    ```


    :param int id: The ID of the location to be exported.
    :param str name: The name of the location to be exported.
    """
    ...
