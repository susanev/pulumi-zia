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
    'GetZIAURLFilteringRulesResult',
    'AwaitableGetZIAURLFilteringRulesResult',
    'get_ziaurl_filtering_rules',
    'get_ziaurl_filtering_rules_output',
]

@pulumi.output_type
class GetZIAURLFilteringRulesResult:
    """
    A collection of values returned by getZIAURLFilteringRules.
    """
    def __init__(__self__, action=None, block_override=None, cbi_profile_id=None, ciparule=None, departments=None, description=None, device_groups=None, device_trust_levels=None, devices=None, end_user_notification_url=None, enforce_time_validity=None, groups=None, id=None, labels=None, last_modified_bies=None, last_modified_time=None, location_groups=None, locations=None, name=None, order=None, override_groups=None, override_users=None, protocols=None, rank=None, request_methods=None, size_quota=None, state=None, time_quota=None, time_windows=None, url_categories=None, user_agent_types=None, users=None, validity_end_time=None, validity_start_time=None, validity_time_zone_id=None):
        if action and not isinstance(action, str):
            raise TypeError("Expected argument 'action' to be a str")
        pulumi.set(__self__, "action", action)
        if block_override and not isinstance(block_override, bool):
            raise TypeError("Expected argument 'block_override' to be a bool")
        pulumi.set(__self__, "block_override", block_override)
        if cbi_profile_id and not isinstance(cbi_profile_id, int):
            raise TypeError("Expected argument 'cbi_profile_id' to be a int")
        pulumi.set(__self__, "cbi_profile_id", cbi_profile_id)
        if ciparule and not isinstance(ciparule, bool):
            raise TypeError("Expected argument 'ciparule' to be a bool")
        pulumi.set(__self__, "ciparule", ciparule)
        if departments and not isinstance(departments, list):
            raise TypeError("Expected argument 'departments' to be a list")
        pulumi.set(__self__, "departments", departments)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if device_groups and not isinstance(device_groups, list):
            raise TypeError("Expected argument 'device_groups' to be a list")
        pulumi.set(__self__, "device_groups", device_groups)
        if device_trust_levels and not isinstance(device_trust_levels, list):
            raise TypeError("Expected argument 'device_trust_levels' to be a list")
        pulumi.set(__self__, "device_trust_levels", device_trust_levels)
        if devices and not isinstance(devices, list):
            raise TypeError("Expected argument 'devices' to be a list")
        pulumi.set(__self__, "devices", devices)
        if end_user_notification_url and not isinstance(end_user_notification_url, str):
            raise TypeError("Expected argument 'end_user_notification_url' to be a str")
        pulumi.set(__self__, "end_user_notification_url", end_user_notification_url)
        if enforce_time_validity and not isinstance(enforce_time_validity, bool):
            raise TypeError("Expected argument 'enforce_time_validity' to be a bool")
        pulumi.set(__self__, "enforce_time_validity", enforce_time_validity)
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
        if order and not isinstance(order, int):
            raise TypeError("Expected argument 'order' to be a int")
        pulumi.set(__self__, "order", order)
        if override_groups and not isinstance(override_groups, list):
            raise TypeError("Expected argument 'override_groups' to be a list")
        pulumi.set(__self__, "override_groups", override_groups)
        if override_users and not isinstance(override_users, list):
            raise TypeError("Expected argument 'override_users' to be a list")
        pulumi.set(__self__, "override_users", override_users)
        if protocols and not isinstance(protocols, list):
            raise TypeError("Expected argument 'protocols' to be a list")
        pulumi.set(__self__, "protocols", protocols)
        if rank and not isinstance(rank, int):
            raise TypeError("Expected argument 'rank' to be a int")
        pulumi.set(__self__, "rank", rank)
        if request_methods and not isinstance(request_methods, list):
            raise TypeError("Expected argument 'request_methods' to be a list")
        pulumi.set(__self__, "request_methods", request_methods)
        if size_quota and not isinstance(size_quota, int):
            raise TypeError("Expected argument 'size_quota' to be a int")
        pulumi.set(__self__, "size_quota", size_quota)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_quota and not isinstance(time_quota, int):
            raise TypeError("Expected argument 'time_quota' to be a int")
        pulumi.set(__self__, "time_quota", time_quota)
        if time_windows and not isinstance(time_windows, list):
            raise TypeError("Expected argument 'time_windows' to be a list")
        pulumi.set(__self__, "time_windows", time_windows)
        if url_categories and not isinstance(url_categories, list):
            raise TypeError("Expected argument 'url_categories' to be a list")
        pulumi.set(__self__, "url_categories", url_categories)
        if user_agent_types and not isinstance(user_agent_types, list):
            raise TypeError("Expected argument 'user_agent_types' to be a list")
        pulumi.set(__self__, "user_agent_types", user_agent_types)
        if users and not isinstance(users, list):
            raise TypeError("Expected argument 'users' to be a list")
        pulumi.set(__self__, "users", users)
        if validity_end_time and not isinstance(validity_end_time, int):
            raise TypeError("Expected argument 'validity_end_time' to be a int")
        pulumi.set(__self__, "validity_end_time", validity_end_time)
        if validity_start_time and not isinstance(validity_start_time, int):
            raise TypeError("Expected argument 'validity_start_time' to be a int")
        pulumi.set(__self__, "validity_start_time", validity_start_time)
        if validity_time_zone_id and not isinstance(validity_time_zone_id, str):
            raise TypeError("Expected argument 'validity_time_zone_id' to be a str")
        pulumi.set(__self__, "validity_time_zone_id", validity_time_zone_id)

    @property
    @pulumi.getter
    def action(self) -> str:
        """
        (String) Action taken when traffic matches rule criteria. Supported values: `ANY`, `NONE`, `BLOCK`, `CAUTION`, `ALLOW`, `ICAP_RESPONSE`
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter(name="blockOverride")
    def block_override(self) -> bool:
        """
        (String) When set to true, a `BLOCK` action triggered by the rule could be overridden. If true and both overrideGroup and overrideUsers are not set, the `BLOCK` triggered by this rule could be overridden for any users. If block)Override is not set, `BLOCK` action cannot be overridden.
        """
        return pulumi.get(self, "block_override")

    @property
    @pulumi.getter(name="cbiProfileId")
    def cbi_profile_id(self) -> int:
        return pulumi.get(self, "cbi_profile_id")

    @property
    @pulumi.getter
    def ciparule(self) -> bool:
        return pulumi.get(self, "ciparule")

    @property
    @pulumi.getter
    def departments(self) -> Sequence['outputs.GetZIAURLFilteringRulesDepartmentResult']:
        """
        (List of Object) The departments to which the Firewall Filtering policy rule applies
        """
        return pulumi.get(self, "departments")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        (String) Additional information about the rule
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="deviceGroups")
    def device_groups(self) -> Sequence['outputs.GetZIAURLFilteringRulesDeviceGroupResult']:
        return pulumi.get(self, "device_groups")

    @property
    @pulumi.getter(name="deviceTrustLevels")
    def device_trust_levels(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "device_trust_levels")

    @property
    @pulumi.getter
    def devices(self) -> Sequence['outputs.GetZIAURLFilteringRulesDeviceResult']:
        return pulumi.get(self, "devices")

    @property
    @pulumi.getter(name="endUserNotificationUrl")
    def end_user_notification_url(self) -> str:
        """
        (String) URL of end user notification page to be displayed when the rule is matched. Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
        """
        return pulumi.get(self, "end_user_notification_url")

    @property
    @pulumi.getter(name="enforceTimeValidity")
    def enforce_time_validity(self) -> bool:
        """
        (String) Enforce a set a validity time period for the URL Filtering rule.
        """
        return pulumi.get(self, "enforce_time_validity")

    @property
    @pulumi.getter
    def groups(self) -> Sequence['outputs.GetZIAURLFilteringRulesGroupResult']:
        """
        (List of Object) The groups to which the Firewall Filtering policy rule applies
        """
        return pulumi.get(self, "groups")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        (Number) Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def labels(self) -> Sequence['outputs.GetZIAURLFilteringRulesLabelResult']:
        return pulumi.get(self, "labels")

    @property
    @pulumi.getter(name="lastModifiedBies")
    def last_modified_bies(self) -> Sequence['outputs.GetZIAURLFilteringRulesLastModifiedByResult']:
        return pulumi.get(self, "last_modified_bies")

    @property
    @pulumi.getter(name="lastModifiedTime")
    def last_modified_time(self) -> int:
        """
        (Number) When the rule was last modified
        """
        return pulumi.get(self, "last_modified_time")

    @property
    @pulumi.getter(name="locationGroups")
    def location_groups(self) -> Sequence['outputs.GetZIAURLFilteringRulesLocationGroupResult']:
        """
        (List of Object) The location groups to which the Firewall Filtering policy rule applies
        """
        return pulumi.get(self, "location_groups")

    @property
    @pulumi.getter
    def locations(self) -> Sequence['outputs.GetZIAURLFilteringRulesLocationResult']:
        """
        (List of Object) The locations to which the Firewall Filtering policy rule applies
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
    @pulumi.getter
    def order(self) -> int:
        """
        (Number) Order of execution of rule with respect to other URL Filtering rules
        """
        return pulumi.get(self, "order")

    @property
    @pulumi.getter(name="overrideGroups")
    def override_groups(self) -> Sequence['outputs.GetZIAURLFilteringRulesOverrideGroupResult']:
        """
        (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any group.
        """
        return pulumi.get(self, "override_groups")

    @property
    @pulumi.getter(name="overrideUsers")
    def override_users(self) -> Sequence['outputs.GetZIAURLFilteringRulesOverrideUserResult']:
        """
        (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any user.
        """
        return pulumi.get(self, "override_users")

    @property
    @pulumi.getter
    def protocols(self) -> Sequence[str]:
        """
        (List of Object) Protocol criteria. Supported values: `SMRULEF_ZPA_BROKERS_RULE`, `ANY_RULE`, `TCP_RULE`, `UDP_RULE`, `DOHTTPS_RULE`, `TUNNELSSL_RULE`, `HTTP_PROXY`, `FOHTTP_RULE`, `FTP_RULE`, `HTTPS_RULE`, `HTTP_RULE`, `SSL_RULE`, `TUNNEL_RULE`.
        """
        return pulumi.get(self, "protocols")

    @property
    @pulumi.getter
    def rank(self) -> int:
        """
        (String) Admin rank of the admin who creates this rule
        """
        return pulumi.get(self, "rank")

    @property
    @pulumi.getter(name="requestMethods")
    def request_methods(self) -> Sequence[str]:
        """
        (String) Request method for which the rule must be applied. If not set, rule will be applied to all methods
        """
        return pulumi.get(self, "request_methods")

    @property
    @pulumi.getter(name="sizeQuota")
    def size_quota(self) -> int:
        """
        (String) Size quota in KB beyond which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
        """
        return pulumi.get(self, "size_quota")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        (String) Rule State
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeQuota")
    def time_quota(self) -> int:
        """
        (String) Time quota in minutes, after which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
        """
        return pulumi.get(self, "time_quota")

    @property
    @pulumi.getter(name="timeWindows")
    def time_windows(self) -> Sequence['outputs.GetZIAURLFilteringRulesTimeWindowResult']:
        """
        (List of Object) The time interval in which the Firewall Filtering policy rule applies
        """
        return pulumi.get(self, "time_windows")

    @property
    @pulumi.getter(name="urlCategories")
    def url_categories(self) -> Sequence[str]:
        """
        (String) List of URL categories for which rule must be applied
        """
        return pulumi.get(self, "url_categories")

    @property
    @pulumi.getter(name="userAgentTypes")
    def user_agent_types(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "user_agent_types")

    @property
    @pulumi.getter
    def users(self) -> Sequence['outputs.GetZIAURLFilteringRulesUserResult']:
        """
        (List of Object) The users to which the Firewall Filtering policy rule applies
        """
        return pulumi.get(self, "users")

    @property
    @pulumi.getter(name="validityEndTime")
    def validity_end_time(self) -> int:
        """
        (Number) If enforceTimeValidity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
        """
        return pulumi.get(self, "validity_end_time")

    @property
    @pulumi.getter(name="validityStartTime")
    def validity_start_time(self) -> int:
        """
        (Number) If enforceTimeValidity is set to true, the URL Filtering rule will be valid starting on this date and time.
        """
        return pulumi.get(self, "validity_start_time")

    @property
    @pulumi.getter(name="validityTimeZoneId")
    def validity_time_zone_id(self) -> str:
        """
        (Number) If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID.
        """
        return pulumi.get(self, "validity_time_zone_id")


class AwaitableGetZIAURLFilteringRulesResult(GetZIAURLFilteringRulesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetZIAURLFilteringRulesResult(
            action=self.action,
            block_override=self.block_override,
            cbi_profile_id=self.cbi_profile_id,
            ciparule=self.ciparule,
            departments=self.departments,
            description=self.description,
            device_groups=self.device_groups,
            device_trust_levels=self.device_trust_levels,
            devices=self.devices,
            end_user_notification_url=self.end_user_notification_url,
            enforce_time_validity=self.enforce_time_validity,
            groups=self.groups,
            id=self.id,
            labels=self.labels,
            last_modified_bies=self.last_modified_bies,
            last_modified_time=self.last_modified_time,
            location_groups=self.location_groups,
            locations=self.locations,
            name=self.name,
            order=self.order,
            override_groups=self.override_groups,
            override_users=self.override_users,
            protocols=self.protocols,
            rank=self.rank,
            request_methods=self.request_methods,
            size_quota=self.size_quota,
            state=self.state,
            time_quota=self.time_quota,
            time_windows=self.time_windows,
            url_categories=self.url_categories,
            user_agent_types=self.user_agent_types,
            users=self.users,
            validity_end_time=self.validity_end_time,
            validity_start_time=self.validity_start_time,
            validity_time_zone_id=self.validity_time_zone_id)


def get_ziaurl_filtering_rules(device_trust_levels: Optional[Sequence[str]] = None,
                               id: Optional[int] = None,
                               name: Optional[str] = None,
                               order: Optional[int] = None,
                               user_agent_types: Optional[Sequence[str]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetZIAURLFilteringRulesResult:
    """
    Use the **zia_url_filtering_rules** data source to get information about a URL filtering rule information for the specified `Name`.

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_ziaurl_filtering_rules(name="Example")
    ```


    :param int id: URL Filtering Rule ID
    :param str name: Name of the URL Filtering policy rule
    :param int order: (Number) Order of execution of rule with respect to other URL Filtering rules
    """
    __args__ = dict()
    __args__['deviceTrustLevels'] = device_trust_levels
    __args__['id'] = id
    __args__['name'] = name
    __args__['order'] = order
    __args__['userAgentTypes'] = user_agent_types
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('zia:index/getZIAURLFilteringRules:getZIAURLFilteringRules', __args__, opts=opts, typ=GetZIAURLFilteringRulesResult).value

    return AwaitableGetZIAURLFilteringRulesResult(
        action=__ret__.action,
        block_override=__ret__.block_override,
        cbi_profile_id=__ret__.cbi_profile_id,
        ciparule=__ret__.ciparule,
        departments=__ret__.departments,
        description=__ret__.description,
        device_groups=__ret__.device_groups,
        device_trust_levels=__ret__.device_trust_levels,
        devices=__ret__.devices,
        end_user_notification_url=__ret__.end_user_notification_url,
        enforce_time_validity=__ret__.enforce_time_validity,
        groups=__ret__.groups,
        id=__ret__.id,
        labels=__ret__.labels,
        last_modified_bies=__ret__.last_modified_bies,
        last_modified_time=__ret__.last_modified_time,
        location_groups=__ret__.location_groups,
        locations=__ret__.locations,
        name=__ret__.name,
        order=__ret__.order,
        override_groups=__ret__.override_groups,
        override_users=__ret__.override_users,
        protocols=__ret__.protocols,
        rank=__ret__.rank,
        request_methods=__ret__.request_methods,
        size_quota=__ret__.size_quota,
        state=__ret__.state,
        time_quota=__ret__.time_quota,
        time_windows=__ret__.time_windows,
        url_categories=__ret__.url_categories,
        user_agent_types=__ret__.user_agent_types,
        users=__ret__.users,
        validity_end_time=__ret__.validity_end_time,
        validity_start_time=__ret__.validity_start_time,
        validity_time_zone_id=__ret__.validity_time_zone_id)


@_utilities.lift_output_func(get_ziaurl_filtering_rules)
def get_ziaurl_filtering_rules_output(device_trust_levels: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                      id: Optional[pulumi.Input[Optional[int]]] = None,
                                      name: Optional[pulumi.Input[Optional[str]]] = None,
                                      order: Optional[pulumi.Input[Optional[int]]] = None,
                                      user_agent_types: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetZIAURLFilteringRulesResult]:
    """
    Use the **zia_url_filtering_rules** data source to get information about a URL filtering rule information for the specified `Name`.

    ```python
    import pulumi
    import pulumi_zia as zia

    example = zia.get_ziaurl_filtering_rules(name="Example")
    ```


    :param int id: URL Filtering Rule ID
    :param str name: Name of the URL Filtering policy rule
    :param int order: (Number) Order of execution of rule with respect to other URL Filtering rules
    """
    ...
