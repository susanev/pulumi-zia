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
from ._inputs import *

__all__ = ['ZIATrafficForwardingGRETunnelArgs', 'ZIATrafficForwardingGRETunnel']

@pulumi.input_type
class ZIATrafficForwardingGRETunnelArgs:
    def __init__(__self__, *,
                 source_ip: pulumi.Input[str],
                 comment: Optional[pulumi.Input[str]] = None,
                 country_code: Optional[pulumi.Input[str]] = None,
                 internal_ip_range: Optional[pulumi.Input[str]] = None,
                 ip_unnumbered: Optional[pulumi.Input[bool]] = None,
                 primary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]] = None,
                 secondary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]] = None,
                 within_country: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a ZIATrafficForwardingGRETunnel resource.
        :param pulumi.Input[str] source_ip: The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        :param pulumi.Input[str] comment: Additional information about this GRE tunnel
        :param pulumi.Input[str] country_code: When within_country is enabled, you must set this to the country code.
        :param pulumi.Input[str] internal_ip_range: The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        :param pulumi.Input[bool] ip_unnumbered: This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        :param pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]] primary_dest_vips: **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]] secondary_dest_vips: The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[bool] within_country: Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        pulumi.set(__self__, "source_ip", source_ip)
        if comment is not None:
            pulumi.set(__self__, "comment", comment)
        if country_code is not None:
            pulumi.set(__self__, "country_code", country_code)
        if internal_ip_range is not None:
            pulumi.set(__self__, "internal_ip_range", internal_ip_range)
        if ip_unnumbered is not None:
            pulumi.set(__self__, "ip_unnumbered", ip_unnumbered)
        if primary_dest_vips is not None:
            pulumi.set(__self__, "primary_dest_vips", primary_dest_vips)
        if secondary_dest_vips is not None:
            pulumi.set(__self__, "secondary_dest_vips", secondary_dest_vips)
        if within_country is not None:
            pulumi.set(__self__, "within_country", within_country)

    @property
    @pulumi.getter(name="sourceIp")
    def source_ip(self) -> pulumi.Input[str]:
        """
        The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        """
        return pulumi.get(self, "source_ip")

    @source_ip.setter
    def source_ip(self, value: pulumi.Input[str]):
        pulumi.set(self, "source_ip", value)

    @property
    @pulumi.getter
    def comment(self) -> Optional[pulumi.Input[str]]:
        """
        Additional information about this GRE tunnel
        """
        return pulumi.get(self, "comment")

    @comment.setter
    def comment(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "comment", value)

    @property
    @pulumi.getter(name="countryCode")
    def country_code(self) -> Optional[pulumi.Input[str]]:
        """
        When within_country is enabled, you must set this to the country code.
        """
        return pulumi.get(self, "country_code")

    @country_code.setter
    def country_code(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "country_code", value)

    @property
    @pulumi.getter(name="internalIpRange")
    def internal_ip_range(self) -> Optional[pulumi.Input[str]]:
        """
        The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        """
        return pulumi.get(self, "internal_ip_range")

    @internal_ip_range.setter
    def internal_ip_range(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "internal_ip_range", value)

    @property
    @pulumi.getter(name="ipUnnumbered")
    def ip_unnumbered(self) -> Optional[pulumi.Input[bool]]:
        """
        This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        """
        return pulumi.get(self, "ip_unnumbered")

    @ip_unnumbered.setter
    def ip_unnumbered(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "ip_unnumbered", value)

    @property
    @pulumi.getter(name="primaryDestVips")
    def primary_dest_vips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]:
        """
        **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "primary_dest_vips")

    @primary_dest_vips.setter
    def primary_dest_vips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]):
        pulumi.set(self, "primary_dest_vips", value)

    @property
    @pulumi.getter(name="secondaryDestVips")
    def secondary_dest_vips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]:
        """
        The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "secondary_dest_vips")

    @secondary_dest_vips.setter
    def secondary_dest_vips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]):
        pulumi.set(self, "secondary_dest_vips", value)

    @property
    @pulumi.getter(name="withinCountry")
    def within_country(self) -> Optional[pulumi.Input[bool]]:
        """
        Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        return pulumi.get(self, "within_country")

    @within_country.setter
    def within_country(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "within_country", value)


@pulumi.input_type
class _ZIATrafficForwardingGRETunnelState:
    def __init__(__self__, *,
                 comment: Optional[pulumi.Input[str]] = None,
                 country_code: Optional[pulumi.Input[str]] = None,
                 internal_ip_range: Optional[pulumi.Input[str]] = None,
                 ip_unnumbered: Optional[pulumi.Input[bool]] = None,
                 last_modification_time: Optional[pulumi.Input[int]] = None,
                 last_modified_bies: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelLastModifiedByArgs']]]] = None,
                 primary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]] = None,
                 secondary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]] = None,
                 source_ip: Optional[pulumi.Input[str]] = None,
                 tunnel_id: Optional[pulumi.Input[int]] = None,
                 within_country: Optional[pulumi.Input[bool]] = None):
        """
        Input properties used for looking up and filtering ZIATrafficForwardingGRETunnel resources.
        :param pulumi.Input[str] comment: Additional information about this GRE tunnel
        :param pulumi.Input[str] country_code: When within_country is enabled, you must set this to the country code.
        :param pulumi.Input[str] internal_ip_range: The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        :param pulumi.Input[bool] ip_unnumbered: This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        :param pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]] primary_dest_vips: **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]] secondary_dest_vips: The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[str] source_ip: The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        :param pulumi.Input[int] tunnel_id: The ID of the GRE tunnel.
        :param pulumi.Input[bool] within_country: Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        if comment is not None:
            pulumi.set(__self__, "comment", comment)
        if country_code is not None:
            pulumi.set(__self__, "country_code", country_code)
        if internal_ip_range is not None:
            pulumi.set(__self__, "internal_ip_range", internal_ip_range)
        if ip_unnumbered is not None:
            pulumi.set(__self__, "ip_unnumbered", ip_unnumbered)
        if last_modification_time is not None:
            pulumi.set(__self__, "last_modification_time", last_modification_time)
        if last_modified_bies is not None:
            pulumi.set(__self__, "last_modified_bies", last_modified_bies)
        if primary_dest_vips is not None:
            pulumi.set(__self__, "primary_dest_vips", primary_dest_vips)
        if secondary_dest_vips is not None:
            pulumi.set(__self__, "secondary_dest_vips", secondary_dest_vips)
        if source_ip is not None:
            pulumi.set(__self__, "source_ip", source_ip)
        if tunnel_id is not None:
            pulumi.set(__self__, "tunnel_id", tunnel_id)
        if within_country is not None:
            pulumi.set(__self__, "within_country", within_country)

    @property
    @pulumi.getter
    def comment(self) -> Optional[pulumi.Input[str]]:
        """
        Additional information about this GRE tunnel
        """
        return pulumi.get(self, "comment")

    @comment.setter
    def comment(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "comment", value)

    @property
    @pulumi.getter(name="countryCode")
    def country_code(self) -> Optional[pulumi.Input[str]]:
        """
        When within_country is enabled, you must set this to the country code.
        """
        return pulumi.get(self, "country_code")

    @country_code.setter
    def country_code(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "country_code", value)

    @property
    @pulumi.getter(name="internalIpRange")
    def internal_ip_range(self) -> Optional[pulumi.Input[str]]:
        """
        The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        """
        return pulumi.get(self, "internal_ip_range")

    @internal_ip_range.setter
    def internal_ip_range(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "internal_ip_range", value)

    @property
    @pulumi.getter(name="ipUnnumbered")
    def ip_unnumbered(self) -> Optional[pulumi.Input[bool]]:
        """
        This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        """
        return pulumi.get(self, "ip_unnumbered")

    @ip_unnumbered.setter
    def ip_unnumbered(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "ip_unnumbered", value)

    @property
    @pulumi.getter(name="lastModificationTime")
    def last_modification_time(self) -> Optional[pulumi.Input[int]]:
        return pulumi.get(self, "last_modification_time")

    @last_modification_time.setter
    def last_modification_time(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "last_modification_time", value)

    @property
    @pulumi.getter(name="lastModifiedBies")
    def last_modified_bies(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelLastModifiedByArgs']]]]:
        return pulumi.get(self, "last_modified_bies")

    @last_modified_bies.setter
    def last_modified_bies(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelLastModifiedByArgs']]]]):
        pulumi.set(self, "last_modified_bies", value)

    @property
    @pulumi.getter(name="primaryDestVips")
    def primary_dest_vips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]:
        """
        **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "primary_dest_vips")

    @primary_dest_vips.setter
    def primary_dest_vips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]):
        pulumi.set(self, "primary_dest_vips", value)

    @property
    @pulumi.getter(name="secondaryDestVips")
    def secondary_dest_vips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]:
        """
        The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "secondary_dest_vips")

    @secondary_dest_vips.setter
    def secondary_dest_vips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]):
        pulumi.set(self, "secondary_dest_vips", value)

    @property
    @pulumi.getter(name="sourceIp")
    def source_ip(self) -> Optional[pulumi.Input[str]]:
        """
        The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        """
        return pulumi.get(self, "source_ip")

    @source_ip.setter
    def source_ip(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "source_ip", value)

    @property
    @pulumi.getter(name="tunnelId")
    def tunnel_id(self) -> Optional[pulumi.Input[int]]:
        """
        The ID of the GRE tunnel.
        """
        return pulumi.get(self, "tunnel_id")

    @tunnel_id.setter
    def tunnel_id(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "tunnel_id", value)

    @property
    @pulumi.getter(name="withinCountry")
    def within_country(self) -> Optional[pulumi.Input[bool]]:
        """
        Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        return pulumi.get(self, "within_country")

    @within_country.setter
    def within_country(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "within_country", value)


class ZIATrafficForwardingGRETunnel(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 comment: Optional[pulumi.Input[str]] = None,
                 country_code: Optional[pulumi.Input[str]] = None,
                 internal_ip_range: Optional[pulumi.Input[str]] = None,
                 ip_unnumbered: Optional[pulumi.Input[bool]] = None,
                 primary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]] = None,
                 secondary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]] = None,
                 source_ip: Optional[pulumi.Input[str]] = None,
                 within_country: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        """
        The **zia_traffic_forwarding_gre_tunnel** resource allows the creation and management of GRE tunnel configuration in the Zscaler Internet Access (ZIA) portal.

        > **Note:** The provider automatically query the Zscaler cloud for the primary and secondary destination datacenter and virtual IP address (VIP) of the GRE tunnel. The parameter can be overriden if needed by setting the parameters: `primary_dest_vip` and `secondary_dest_vip`.

        ## Example Usage

        ```python
        import pulumi
        import zscaler_pulumi_zia as zia

        # ZIA Traffic Forwarding - Static IP
        example_zia_traffic_forwarding_static_ip = zia.ZIATrafficForwardingStaticIP("exampleZIATrafficForwardingStaticIP",
            ip_address="1.1.1.1",
            routable_ip=True,
            comment="Example",
            geo_override=True,
            latitude=37.418171,
            longitude=-121.95314)
        # Creates a numbered GRE Tunnel
        example_zia_traffic_forwarding_gre_tunnel = zia.ZIATrafficForwardingGRETunnel("exampleZIATrafficForwardingGRETunnel",
            source_ip=example_zia_traffic_forwarding_static_ip.ip_address,
            comment="Example",
            within_country=True,
            country_code="US",
            ip_unnumbered=False,
            opts=pulumi.ResourceOptions(depends_on=[example_zia_traffic_forwarding_static_ip]))
        ```

        > **Note:** The provider will automatically query and set the Zscaler cloud for the next available `/29` internal IP range to be used in a numbered GRE tunnel.

        ```python
        import pulumi
        import zscaler_pulumi_zia as zia

        # ZIA Traffic Forwarding - Static IP
        example = zia.ZIATrafficForwardingStaticIP("example",
            ip_address="1.1.1.1",
            routable_ip=True,
            comment="Example",
            geo_override=True,
            latitude=37.418171,
            longitude=-121.95314)
        # Creates an unnumbered GRE Tunnel
        telus_home_internet01_gre01 = zia.ZIATrafficForwardingGRETunnel("telusHomeInternet01Gre01",
            source_ip=example.ip_address,
            comment="Example",
            within_country=True,
            country_code="CA",
            ip_unnumbered=True,
            opts=pulumi.ResourceOptions(depends_on=[example]))
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] comment: Additional information about this GRE tunnel
        :param pulumi.Input[str] country_code: When within_country is enabled, you must set this to the country code.
        :param pulumi.Input[str] internal_ip_range: The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        :param pulumi.Input[bool] ip_unnumbered: This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]] primary_dest_vips: **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]] secondary_dest_vips: The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[str] source_ip: The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        :param pulumi.Input[bool] within_country: Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ZIATrafficForwardingGRETunnelArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        The **zia_traffic_forwarding_gre_tunnel** resource allows the creation and management of GRE tunnel configuration in the Zscaler Internet Access (ZIA) portal.

        > **Note:** The provider automatically query the Zscaler cloud for the primary and secondary destination datacenter and virtual IP address (VIP) of the GRE tunnel. The parameter can be overriden if needed by setting the parameters: `primary_dest_vip` and `secondary_dest_vip`.

        ## Example Usage

        ```python
        import pulumi
        import zscaler_pulumi_zia as zia

        # ZIA Traffic Forwarding - Static IP
        example_zia_traffic_forwarding_static_ip = zia.ZIATrafficForwardingStaticIP("exampleZIATrafficForwardingStaticIP",
            ip_address="1.1.1.1",
            routable_ip=True,
            comment="Example",
            geo_override=True,
            latitude=37.418171,
            longitude=-121.95314)
        # Creates a numbered GRE Tunnel
        example_zia_traffic_forwarding_gre_tunnel = zia.ZIATrafficForwardingGRETunnel("exampleZIATrafficForwardingGRETunnel",
            source_ip=example_zia_traffic_forwarding_static_ip.ip_address,
            comment="Example",
            within_country=True,
            country_code="US",
            ip_unnumbered=False,
            opts=pulumi.ResourceOptions(depends_on=[example_zia_traffic_forwarding_static_ip]))
        ```

        > **Note:** The provider will automatically query and set the Zscaler cloud for the next available `/29` internal IP range to be used in a numbered GRE tunnel.

        ```python
        import pulumi
        import zscaler_pulumi_zia as zia

        # ZIA Traffic Forwarding - Static IP
        example = zia.ZIATrafficForwardingStaticIP("example",
            ip_address="1.1.1.1",
            routable_ip=True,
            comment="Example",
            geo_override=True,
            latitude=37.418171,
            longitude=-121.95314)
        # Creates an unnumbered GRE Tunnel
        telus_home_internet01_gre01 = zia.ZIATrafficForwardingGRETunnel("telusHomeInternet01Gre01",
            source_ip=example.ip_address,
            comment="Example",
            within_country=True,
            country_code="CA",
            ip_unnumbered=True,
            opts=pulumi.ResourceOptions(depends_on=[example]))
        ```

        :param str resource_name: The name of the resource.
        :param ZIATrafficForwardingGRETunnelArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ZIATrafficForwardingGRETunnelArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 comment: Optional[pulumi.Input[str]] = None,
                 country_code: Optional[pulumi.Input[str]] = None,
                 internal_ip_range: Optional[pulumi.Input[str]] = None,
                 ip_unnumbered: Optional[pulumi.Input[bool]] = None,
                 primary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]] = None,
                 secondary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]] = None,
                 source_ip: Optional[pulumi.Input[str]] = None,
                 within_country: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ZIATrafficForwardingGRETunnelArgs.__new__(ZIATrafficForwardingGRETunnelArgs)

            __props__.__dict__["comment"] = comment
            __props__.__dict__["country_code"] = country_code
            __props__.__dict__["internal_ip_range"] = internal_ip_range
            __props__.__dict__["ip_unnumbered"] = ip_unnumbered
            __props__.__dict__["primary_dest_vips"] = primary_dest_vips
            __props__.__dict__["secondary_dest_vips"] = secondary_dest_vips
            if source_ip is None and not opts.urn:
                raise TypeError("Missing required property 'source_ip'")
            __props__.__dict__["source_ip"] = source_ip
            __props__.__dict__["within_country"] = within_country
            __props__.__dict__["last_modification_time"] = None
            __props__.__dict__["last_modified_bies"] = None
            __props__.__dict__["tunnel_id"] = None
        super(ZIATrafficForwardingGRETunnel, __self__).__init__(
            'zia:index/zIATrafficForwardingGRETunnel:ZIATrafficForwardingGRETunnel',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            comment: Optional[pulumi.Input[str]] = None,
            country_code: Optional[pulumi.Input[str]] = None,
            internal_ip_range: Optional[pulumi.Input[str]] = None,
            ip_unnumbered: Optional[pulumi.Input[bool]] = None,
            last_modification_time: Optional[pulumi.Input[int]] = None,
            last_modified_bies: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelLastModifiedByArgs']]]]] = None,
            primary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]]] = None,
            secondary_dest_vips: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]]] = None,
            source_ip: Optional[pulumi.Input[str]] = None,
            tunnel_id: Optional[pulumi.Input[int]] = None,
            within_country: Optional[pulumi.Input[bool]] = None) -> 'ZIATrafficForwardingGRETunnel':
        """
        Get an existing ZIATrafficForwardingGRETunnel resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] comment: Additional information about this GRE tunnel
        :param pulumi.Input[str] country_code: When within_country is enabled, you must set this to the country code.
        :param pulumi.Input[str] internal_ip_range: The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        :param pulumi.Input[bool] ip_unnumbered: This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelPrimaryDestVipArgs']]]] primary_dest_vips: **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ZIATrafficForwardingGRETunnelSecondaryDestVipArgs']]]] secondary_dest_vips: The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        :param pulumi.Input[str] source_ip: The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        :param pulumi.Input[int] tunnel_id: The ID of the GRE tunnel.
        :param pulumi.Input[bool] within_country: Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ZIATrafficForwardingGRETunnelState.__new__(_ZIATrafficForwardingGRETunnelState)

        __props__.__dict__["comment"] = comment
        __props__.__dict__["country_code"] = country_code
        __props__.__dict__["internal_ip_range"] = internal_ip_range
        __props__.__dict__["ip_unnumbered"] = ip_unnumbered
        __props__.__dict__["last_modification_time"] = last_modification_time
        __props__.__dict__["last_modified_bies"] = last_modified_bies
        __props__.__dict__["primary_dest_vips"] = primary_dest_vips
        __props__.__dict__["secondary_dest_vips"] = secondary_dest_vips
        __props__.__dict__["source_ip"] = source_ip
        __props__.__dict__["tunnel_id"] = tunnel_id
        __props__.__dict__["within_country"] = within_country
        return ZIATrafficForwardingGRETunnel(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def comment(self) -> pulumi.Output[Optional[str]]:
        """
        Additional information about this GRE tunnel
        """
        return pulumi.get(self, "comment")

    @property
    @pulumi.getter(name="countryCode")
    def country_code(self) -> pulumi.Output[str]:
        """
        When within_country is enabled, you must set this to the country code.
        """
        return pulumi.get(self, "country_code")

    @property
    @pulumi.getter(name="internalIpRange")
    def internal_ip_range(self) -> pulumi.Output[str]:
        """
        The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ip_unnumbered` is set to `false`.
        """
        return pulumi.get(self, "internal_ip_range")

    @property
    @pulumi.getter(name="ipUnnumbered")
    def ip_unnumbered(self) -> pulumi.Output[bool]:
        """
        This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
        """
        return pulumi.get(self, "ip_unnumbered")

    @property
    @pulumi.getter(name="lastModificationTime")
    def last_modification_time(self) -> pulumi.Output[int]:
        return pulumi.get(self, "last_modification_time")

    @property
    @pulumi.getter(name="lastModifiedBies")
    def last_modified_bies(self) -> pulumi.Output[Sequence['outputs.ZIATrafficForwardingGRETunnelLastModifiedBy']]:
        return pulumi.get(self, "last_modified_bies")

    @property
    @pulumi.getter(name="primaryDestVips")
    def primary_dest_vips(self) -> pulumi.Output[Sequence['outputs.ZIATrafficForwardingGRETunnelPrimaryDestVip']]:
        """
        **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "primary_dest_vips")

    @property
    @pulumi.getter(name="secondaryDestVips")
    def secondary_dest_vips(self) -> pulumi.Output[Sequence['outputs.ZIATrafficForwardingGRETunnelSecondaryDestVip']]:
        """
        The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
        """
        return pulumi.get(self, "secondary_dest_vips")

    @property
    @pulumi.getter(name="sourceIp")
    def source_ip(self) -> pulumi.Output[str]:
        """
        The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
        """
        return pulumi.get(self, "source_ip")

    @property
    @pulumi.getter(name="tunnelId")
    def tunnel_id(self) -> pulumi.Output[int]:
        """
        The ID of the GRE tunnel.
        """
        return pulumi.get(self, "tunnel_id")

    @property
    @pulumi.getter(name="withinCountry")
    def within_country(self) -> pulumi.Output[bool]:
        """
        Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
        """
        return pulumi.get(self, "within_country")

