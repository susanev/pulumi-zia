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
    'GetZIAFirewallFilteringRuleResult',
    'AwaitableGetZIAFirewallFilteringRuleResult',
    'get_zia_firewall_filtering_rule',
    'get_zia_firewall_filtering_rule_output',
]

@pulumi.output_type
class GetZIAFirewallFilteringRuleResult:
    """
    A collection of values returned by getZIAFirewallFilteringRule.
    """
    def __init__(__self__, access_control=None, action=None, app_service_groups=None, app_services=None, default_rule=None, departments=None, description=None, dest_addresses=None, dest_countries=None, dest_ip_categories=None, dest_ip_groups=None, enable_full_logging=None, groups=None, id=None, labels=None, last_modified_bies=None, last_modified_time=None, location_groups=None, locations=None, name=None, nw_application_groups=None, nw_applications=None, nw_service_groups=None, nw_services=None, order=None, predefined=None, rank=None, src_ip_groups=None, src_ips=None, state=None, time_windows=None, users=None):
        if access_control and not isinstance(access_control, str):
            raise TypeError("Expected argument 'access_control' to be a str")
        pulumi.set(__self__, "access_control", access_control)
        if action and not isinstance(action, str):
            raise TypeError("Expected argument 'action' to be a str")
        pulumi.set(__self__, "action", action)
        if app_service_groups and not isinstance(app_service_groups, list):
            raise TypeError("Expected argument 'app_service_groups' to be a list")
        pulumi.set(__self__, "app_service_groups", app_service_groups)
        if app_services and not isinstance(app_services, list):
            raise TypeError("Expected argument 'app_services' to be a list")
        pulumi.set(__self__, "app_services", app_services)
        if default_rule and not isinstance(default_rule, bool):
            raise TypeError("Expected argument 'default_rule' to be a bool")
        pulumi.set(__self__, "default_rule", default_rule)
        if departments and not isinstance(departments, list):
            raise TypeError("Expected argument 'departments' to be a list")
        pulumi.set(__self__, "departments", departments)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if dest_addresses and not isinstance(dest_addresses, list):
            raise TypeError("Expected argument 'dest_addresses' to be a list")
        pulumi.set(__self__, "dest_addresses", dest_addresses)
        if dest_countries and not isinstance(dest_countries, list):
            raise TypeError("Expected argument 'dest_countries' to be a list")
        pulumi.set(__self__, "dest_countries", dest_countries)
        if dest_ip_categories and not isinstance(dest_ip_categories, list):
            raise TypeError("Expected argument 'dest_ip_categories' to be a list")
        pulumi.set(__self__, "dest_ip_categories", dest_ip_categories)
        if dest_ip_groups and not isinstance(dest_ip_groups, list):
            raise TypeError("Expected argument 'dest_ip_groups' to be a list")
        pulumi.set(__self__, "dest_ip_groups", dest_ip_groups)
        if enable_full_logging and not isinstance(enable_full_logging, bool):
            raise TypeError("Expected argument 'enable_full_logging' to be a bool")
        pulumi.set(__self__, "enable_full_logging", enable_full_logging)
        if groups and not isinstance(groups, list):
            raise TypeError("Expected argument 'groups' to be a list")
        pulumi.set(__self__, "groups", groups)
        if id and not isinstance(id, int):
            raise TypeError("Expected argument 'id' to be a int")
        pulumi.set(__self__, "id", id)
        if labels and not isinstance(labels, list):
            raise TypeError("Expected argument 'labels' to be a list")
        pulumi.set(__self__, "labels", labels)
        if last_modified_bies and not isinstance(last_modified_bies, list):
            raise TypeError("Expected argument 'last_modified_bies' to be a list")
        pulumi.set(__self__, "last_modified_bies", last_modified_bies)
        if last_modified_time and not isinstance(last_modified_time, int):
            raise TypeError("Expected argument 'last_modified_time' to be a int")
        pulumi.set(__self__, "last_modified_time", last_modified_time)
        if location_groups and not isinstance(location_groups, list):
            raise TypeError("Expected argument 'location_groups' to be a list")
        pulumi.set(__self__, "location_groups", location_groups)
        if locations and not isinstance(locations, list):
            raise TypeError("Expected argument 'locations' to be a list")
        pulumi.set(__self__, "locations", locations)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if nw_application_groups and not isinstance(nw_application_groups, list):
            raise TypeError("Expected argument 'nw_application_groups' to be a list")
        pulumi.set(__self__, "nw_application_groups", nw_application_groups)
        if nw_applications and not isinstance(nw_applications, list):
            raise TypeError("Expected argument 'nw_applications' to be a list")
        pulumi.set(__self__, "nw_applications", nw_applications)
        if nw_service_groups and not isinstance(nw_service_groups, list):
            raise TypeError("Expected argument 'nw_service_groups' to be a list")
        pulumi.set(__self__, "nw_service_groups", nw_service_groups)
        if nw_services and not isinstance(nw_services, list):
            raise TypeError("Expected argument 'nw_services' to be a list")
        pulumi.set(__self__, "nw_services", nw_services)
        if order and not isinstance(order, int):
            raise TypeError("Expected argument 'order' to be a int")
        pulumi.set(__self__, "order", order)
        if predefined and not isinstance(predefined, bool):
            raise TypeError("Expected argument 'predefined' to be a bool")
        pulumi.set(__self__, "predefined", predefined)
        if rank and not isinstance(rank, int):
            raise TypeError("Expected argument 'rank' to be a int")
        pulumi.set(__self__, "rank", rank)
        if src_ip_groups and not isinstance(src_ip_groups, list):
            raise TypeError("Expected argument 'src_ip_groups' to be a list")
        pulumi.set(__self__, "src_ip_groups", src_ip_groups)
        if src_ips and not isinstance(src_ips, list):
            raise TypeError("Expected argument 'src_ips' to be a list")
        pulumi.set(__self__, "src_ips", src_ips)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_windows and not isinstance(time_windows, list):
            raise TypeError("Expected argument 'time_windows' to be a list")
        pulumi.set(__self__, "time_windows", time_windows)
        if users and not isinstance(users, list):
            raise TypeError("Expected argument 'users' to be a list")
        pulumi.set(__self__, "users", users)

    @property
    @pulumi.getter(name="accessControl")
    def access_control(self) -> str:
        """
        (String)
        """
        return pulumi.get(self, "access_control")

    @property
    @pulumi.getter
    def action(self) -> Optional[str]:
        """
        (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter(name="appServiceGroups")
    def app_service_groups(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleAppServiceGroupResult']:
        """
        Application service groups on which this rule is applied
        """
        return pulumi.get(self, "app_service_groups")

    @property
    @pulumi.getter(name="appServices")
    def app_services(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleAppServiceResult']:
        """
        Application services on which this rule is applied
        """
        return pulumi.get(self, "app_services")

    @property
    @pulumi.getter(name="defaultRule")
    def default_rule(self) -> bool:
        """
        (Boolean)
        """
        return pulumi.get(self, "default_rule")

    @property
    @pulumi.getter
    def departments(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleDepartmentResult']:
        """
        (Optional) Apply to any number of departments When not used it implies `Any` to apply the rule to all departments.
        """
        return pulumi.get(self, "departments")

    @property
    @pulumi.getter
    def description(self) -> Optional[str]:
        """
        (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="destAddresses")
    def dest_addresses(self) -> Sequence[str]:
        """
        ** - (Optional) -  IP addresses and fully qualified domain names (FQDNs), if the domain has multiple destination IP addresses or if its IP addresses may change. For IP addresses, you can enter individual IP addresses, subnets, or address ranges. If adding multiple items, hit Enter after each entry.
        """
        return pulumi.get(self, "dest_addresses")

    @property
    @pulumi.getter(name="destCountries")
    def dest_countries(self) -> Sequence[str]:
        """
        ** - (Optional) Identify destinations based on the location of a server, select Any to apply the rule to all countries or select the countries to which you want to control traffic.
        """
        return pulumi.get(self, "dest_countries")

    @property
    @pulumi.getter(name="destIpCategories")
    def dest_ip_categories(self) -> Sequence[str]:
        """
        ** - (Optional) identify destinations based on the URL category of the domain, select Any to apply the rule to all categories or select the specific categories you want to control.
        """
        return pulumi.get(self, "dest_ip_categories")

    @property
    @pulumi.getter(name="destIpGroups")
    def dest_ip_groups(self) -> Sequence[str]:
        """
        ** - (Optional) Any number of destination IP address groups that you want to control with this rule.
        """
        return pulumi.get(self, "dest_ip_groups")

    @property
    @pulumi.getter(name="enableFullLogging")
    def enable_full_logging(self) -> bool:
        """
        (Boolean)
        """
        return pulumi.get(self, "enable_full_logging")

    @property
    @pulumi.getter
    def groups(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleGroupResult']:
        """
        (Optional) You can manually select up to `8` groups. When not used it implies `Any` to apply the rule to all groups.
        """
        return pulumi.get(self, "groups")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        (Number) The ID of this resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def labels(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleLabelResult']:
        """
        Labels that are applicable to the rule.
        """
        return pulumi.get(self, "labels")

    @property
    @pulumi.getter(name="lastModifiedBies")
    def last_modified_bies(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleLastModifiedByResult']:
        return pulumi.get(self, "last_modified_bies")

    @property
    @pulumi.getter(name="lastModifiedTime")
    def last_modified_time(self) -> Optional[int]:
        """
        (Number)
        """
        return pulumi.get(self, "last_modified_time")

    @property
    @pulumi.getter(name="locationGroups")
    def location_groups(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleLocationGroupResult']:
        """
        (Optional) You can manually select up to `32` location groups. When not used it implies `Any` to apply the rule to all location groups.
        """
        return pulumi.get(self, "location_groups")

    @property
    @pulumi.getter
    def locations(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleLocationResult']:
        """
        (Optional) You can manually select up to `8` locations. When not used it implies `Any` to apply the rule to all groups.
        """
        return pulumi.get(self, "locations")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        (String) The configured name of the entity
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="nwApplicationGroups")
    def nw_application_groups(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleNwApplicationGroupResult']:
        """
        (Optional) Any number of application groups that you want to control with this rule. The service provides predefined applications that you can group, but not modify
        """
        return pulumi.get(self, "nw_application_groups")

    @property
    @pulumi.getter(name="nwApplications")
    def nw_applications(self) -> Sequence[str]:
        """
        (Optional) When not used it applies the rule to all applications. The service provides predefined applications, which you can group, but not modify.
        """
        return pulumi.get(self, "nw_applications")

    @property
    @pulumi.getter(name="nwServiceGroups")
    def nw_service_groups(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleNwServiceGroupResult']:
        """
        (Optional) Any number of predefined or custom network service groups to which the rule applies.
        """
        return pulumi.get(self, "nw_service_groups")

    @property
    @pulumi.getter(name="nwServices")
    def nw_services(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleNwServiceResult']:
        """
        (Optional) When not used it applies the rule to all network services or you can select specific network services. The Zscaler firewall has predefined services and you can configure up to `1,024` additional custom services.
        """
        return pulumi.get(self, "nw_services")

    @property
    @pulumi.getter
    def order(self) -> int:
        """
        (Required) Policy rules are evaluated in ascending numerical order (Rule 1 before Rule 2, and so on), and the Rule Order reflects this rule's place in the order.
        """
        return pulumi.get(self, "order")

    @property
    @pulumi.getter
    def predefined(self) -> bool:
        """
        (Boolean)
        """
        return pulumi.get(self, "predefined")

    @property
    @pulumi.getter
    def rank(self) -> int:
        """
        (Optional) By default, the admin ranking is disabled. To use this feature, you must enable admin rank. The default value is `7`.
        """
        return pulumi.get(self, "rank")

    @property
    @pulumi.getter(name="srcIpGroups")
    def src_ip_groups(self) -> Sequence[str]:
        """
        (Optional) Any number of source IP address groups that you want to control with this rule.
        """
        return pulumi.get(self, "src_ip_groups")

    @property
    @pulumi.getter(name="srcIps")
    def src_ips(self) -> Sequence[str]:
        """
        (Optional) You can enter individual IP addresses, subnets, or address ranges.
        """
        return pulumi.get(self, "src_ips")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeWindows")
    def time_windows(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleTimeWindowResult']:
        """
        (Optional) You can manually select up to `2` time intervals. When not used it implies `always` to apply the rule to all time intervals.
        """
        return pulumi.get(self, "time_windows")

    @property
    @pulumi.getter
    def users(self) -> Sequence['outputs.GetZIAFirewallFilteringRuleUserResult']:
        """
        (Optional) You can manually select up to `4` general and/or special users. When not used it implies `Any` to apply the rule to all users.
        """
        return pulumi.get(self, "users")


class AwaitableGetZIAFirewallFilteringRuleResult(GetZIAFirewallFilteringRuleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIAFirewallFilteringRuleResult(
            access_control=self.access_control,
            action=self.action,
            app_service_groups=self.app_service_groups,
            app_services=self.app_services,
            default_rule=self.default_rule,
            departments=self.departments,
            description=self.description,
            dest_addresses=self.dest_addresses,
            dest_countries=self.dest_countries,
            dest_ip_categories=self.dest_ip_categories,
            dest_ip_groups=self.dest_ip_groups,
            enable_full_logging=self.enable_full_logging,
            groups=self.groups,
            id=self.id,
            labels=self.labels,
            last_modified_bies=self.last_modified_bies,
            last_modified_time=self.last_modified_time,
            location_groups=self.location_groups,
            locations=self.locations,
            name=self.name,
            nw_application_groups=self.nw_application_groups,
            nw_applications=self.nw_applications,
            nw_service_groups=self.nw_service_groups,
            nw_services=self.nw_services,
            order=self.order,
            predefined=self.predefined,
            rank=self.rank,
            src_ip_groups=self.src_ip_groups,
            src_ips=self.src_ips,
            state=self.state,
            time_windows=self.time_windows,
            users=self.users)


def get_zia_firewall_filtering_rule(action: Optional[str] = None,
                                    description: Optional[str] = None,
                                    id: Optional[int] = None,
                                    last_modified_time: Optional[int] = None,
                                    name: Optional[str] = None,
                                    state: Optional[str] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIAFirewallFilteringRuleResult:
    """
    Use the **zia_firewall_filtering_rule** data source to get information about a cloud firewall rule available in the Zscaler Internet Access cloud firewall.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_zia_firewall_filtering_rule(name="Office 365 One Click Rule")
    ```


    :param str action: (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
    :param str description: (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
    :param int id: Unique identifier for the Firewall Filtering policy rule
    :param int last_modified_time: (Number)
    :param str name: Name of the Firewall Filtering policy rule
    :param str state: (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
    """
    __args__ = dict()
    __args__['action'] = action
    __args__['description'] = description
    __args__['id'] = id
    __args__['lastModifiedTime'] = last_modified_time
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIAFirewallFilteringRule:getZIAFirewallFilteringRule', __args__, opts=opts, typ=GetZIAFirewallFilteringRuleResult).value

    return AwaitableGetZIAFirewallFilteringRuleResult(
        access_control=__ret__.access_control,
        action=__ret__.action,
        app_service_groups=__ret__.app_service_groups,
        app_services=__ret__.app_services,
        default_rule=__ret__.default_rule,
        departments=__ret__.departments,
        description=__ret__.description,
        dest_addresses=__ret__.dest_addresses,
        dest_countries=__ret__.dest_countries,
        dest_ip_categories=__ret__.dest_ip_categories,
        dest_ip_groups=__ret__.dest_ip_groups,
        enable_full_logging=__ret__.enable_full_logging,
        groups=__ret__.groups,
        id=__ret__.id,
        labels=__ret__.labels,
        last_modified_bies=__ret__.last_modified_bies,
        last_modified_time=__ret__.last_modified_time,
        location_groups=__ret__.location_groups,
        locations=__ret__.locations,
        name=__ret__.name,
        nw_application_groups=__ret__.nw_application_groups,
        nw_applications=__ret__.nw_applications,
        nw_service_groups=__ret__.nw_service_groups,
        nw_services=__ret__.nw_services,
        order=__ret__.order,
        predefined=__ret__.predefined,
        rank=__ret__.rank,
        src_ip_groups=__ret__.src_ip_groups,
        src_ips=__ret__.src_ips,
        state=__ret__.state,
        time_windows=__ret__.time_windows,
        users=__ret__.users)


@_utilities.lift_output_func(get_zia_firewall_filtering_rule)
def get_zia_firewall_filtering_rule_output(action: Optional[pulumi.Input[Optional[str]]] = None,
                                           description: Optional[pulumi.Input[Optional[str]]] = None,
                                           id: Optional[pulumi.Input[Optional[int]]] = None,
                                           last_modified_time: Optional[pulumi.Input[Optional[int]]] = None,
                                           name: Optional[pulumi.Input[Optional[str]]] = None,
                                           state: Optional[pulumi.Input[Optional[str]]] = None,
                                           opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetZIAFirewallFilteringRuleResult]:
    """
    Use the **zia_firewall_filtering_rule** data source to get information about a cloud firewall rule available in the Zscaler Internet Access cloud firewall.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_zia_firewall_filtering_rule(name="Office 365 One Click Rule")
    ```


    :param str action: (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
    :param str description: (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
    :param int id: Unique identifier for the Firewall Filtering policy rule
    :param int last_modified_time: (Number)
    :param str name: Name of the Firewall Filtering policy rule
    :param str state: (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
    """
    ...
