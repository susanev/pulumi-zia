// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";

export interface GetZIAAdminUsersAdminScope {
    /**
     * (String) Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
     */
    scopeEntities: outputs.GetZIAAdminUsersAdminScopeScopeEntity[];
    /**
     * (Number) Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
     */
    scopeGroupMemberEntities: outputs.GetZIAAdminUsersAdminScopeScopeGroupMemberEntity[];
    /**
     * (String) The admin scope type. The attribute name is subject to change.
     */
    type: string;
}

export interface GetZIAAdminUsersAdminScopeScopeEntity {
    extensions: {[key: string]: string};
    /**
     * The ID of the admin user to be exported.
     */
    id: number;
    /**
     * (String)
     */
    name: string;
}

export interface GetZIAAdminUsersAdminScopeScopeGroupMemberEntity {
    extensions: {[key: string]: string};
    /**
     * The ID of the admin user to be exported.
     */
    id: number;
    /**
     * (String)
     */
    name: string;
}

export interface GetZIAAdminUsersExecMobileAppToken {
    /**
     * (String)
     */
    cloud: string;
    /**
     * (Number)
     */
    createTime: number;
    /**
     * (String)
     */
    deviceId: string;
    /**
     * (String)
     */
    deviceName: string;
    /**
     * (String)
     */
    name: string;
    /**
     * (Number)
     */
    orgId: number;
    /**
     * (String)
     */
    token: string;
    /**
     * (Number)
     */
    tokenExpiry: number;
    /**
     * (String)
     */
    tokenId: string;
}

export interface GetZIAAdminUsersRole {
    extensions: {[key: string]: string};
    /**
     * The ID of the admin user to be exported.
     */
    id: number;
    /**
     * (String)
     */
    name: string;
}

export interface GetZIADLPDictionariesExactDataMatchDetail {
    dictionaryEdmMappingId: number;
    primaryField: number;
    schemaId: number;
    secondaryFieldMatchOn: string;
    secondaryFields: number[];
}

export interface GetZIADLPDictionariesIdmProfileMatchAccuracy {
    adpIdmProfiles: outputs.GetZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile[];
    matchAccuracy: string;
}

export interface GetZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile {
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the DLP dictionary
     */
    id: number;
}

export interface GetZIADLPDictionariesPattern {
    /**
     * (String) The action applied to a DLP dictionary using patterns
     */
    action: string;
    /**
     * (String) DLP dictionary pattern
     */
    pattern: string;
}

export interface GetZIADLPDictionariesPhrase {
    /**
     * (String) The action applied to a DLP dictionary using patterns
     */
    action: string;
    phrase: string;
}

export interface GetZIADLPWebRulesAuditor {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesDepartment {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesDlpEngine {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesExcludedDepartment {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface GetZIADLPWebRulesExcludedGroup {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface GetZIADLPWebRulesExcludedUser {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface GetZIADLPWebRulesGroup {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesIcapServer {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesLabel {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesLastModifiedBy {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesLocation {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesLocationGroup {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesNotificationTemplate {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesTimeWindow {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesUrlCategory {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIADLPWebRulesUser {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    /**
     * The DLP policy rule name.
     * rules.
     */
    name: string;
}

export interface GetZIAFirewallFilteringNetworkServiceGroupsService {
    /**
     * (String)
     */
    description: string;
    /**
     * The ID of the ip source group to be exported.
     */
    id: number;
    /**
     * (Bool) - Default: false
     */
    isNameL10nTag: boolean;
    /**
     * The name of the ip source group to be exported.
     */
    name?: string;
}

export interface GetZIAFirewallFilteringNetworkServicesDestTcpPort {
    /**
     * (Number)
     */
    end: number;
    /**
     * (Number)
     */
    start: number;
}

export interface GetZIAFirewallFilteringNetworkServicesDestUdpPort {
    /**
     * (Number)
     */
    end: number;
    /**
     * (Number)
     */
    start: number;
}

export interface GetZIAFirewallFilteringNetworkServicesSrcTcpPort {
    /**
     * (Number)
     */
    end: number;
    /**
     * (Number)
     */
    start: number;
}

export interface GetZIAFirewallFilteringNetworkServicesSrcUdpPort {
    /**
     * (Number)
     */
    end: number;
    /**
     * (Number)
     */
    start: number;
}

export interface GetZIAFirewallFilteringRuleAppService {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleAppServiceGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleDepartment {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleLabel {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleLastModifiedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleLocation {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleLocationGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleNwApplicationGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleNwService {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleNwServiceGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleTimeWindow {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIAFirewallFilteringRuleUser {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteria {
    /**
     * (Block List)
     */
    cities?: outputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCity[];
    /**
     * (List of String) One or more countries from a predefined set
     */
    countries?: string[];
    /**
     * (Boolean) Enable Bandwidth Control. When set to true, Bandwidth Control is enabled for the location.
     */
    enableBandwidthControl: boolean;
    /**
     * (Boolean) Enable Caution. When set to true, a caution notifcation is enabled for the location.
     */
    enableCaution: boolean;
    /**
     * (Boolean) Enable `XFF` Forwarding. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header.
     */
    enableXffForwarding: boolean;
    /**
     * (Boolean) Enable AUP. When set to true, AUP is enabled for the location.
     */
    enforceAup: boolean;
    /**
     * (Boolean) Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled.
     */
    enforceAuthentication: boolean;
    /**
     * (Boolean) Enable Firewall. When set to true, Firewall is enabled for the location.
     */
    enforceFirewallControl: boolean;
    /**
     * (Block List)
     */
    managedBies: outputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedBy[];
    /**
     * Location group name
     */
    names?: outputs.GetZIALocationGroupsDynamicLocationGroupCriteriaName[];
    /**
     * (List of String) One or more location profiles from a predefined set
     */
    profiles?: string[];
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaCity {
    /**
     * (String) String value to be matched or partially matched
     */
    matchString?: string;
    /**
     * (String) Operator that performs match action
     */
    matchType?: string;
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaManagedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the location group
     */
    id: number;
    /**
     * Location group name
     */
    name: string;
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaName {
    /**
     * (String) String value to be matched or partially matched
     */
    matchString?: string;
    /**
     * (String) Operator that performs match action
     */
    matchType?: string;
}

export interface GetZIALocationGroupsLastModUser {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the location group
     */
    id: number;
    /**
     * Location group name
     */
    name: string;
}

export interface GetZIALocationGroupsLocation {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifier for the location group
     */
    id: number;
    /**
     * Location group name
     */
    name: string;
}

export interface GetZIALocationManagementVpnCredential {
    /**
     * (String) Additional information about this VPN credential.
     * Additional information about this VPN credential.
     */
    comments: string;
    /**
     * (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
     */
    fqdn: string;
    /**
     * The ID of the location to be exported.
     */
    id: number;
    /**
     * (List of Object)
     */
    locations: outputs.GetZIALocationManagementVpnCredentialLocation[];
    /**
     * (List of Object)
     */
    managedBies: outputs.GetZIALocationManagementVpnCredentialManagedBy[];
    /**
     * (String) Pre-shared key. This is a required field for `UFQDN` and IP auth type.
     */
    preSharedKey: string;
    /**
     * (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
     */
    type: string;
}

export interface GetZIALocationManagementVpnCredentialLocation {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * The ID of the location to be exported.
     */
    id: number;
    /**
     * The name of the location to be exported.
     */
    name: string;
}

export interface GetZIALocationManagementVpnCredentialManagedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * The ID of the location to be exported.
     */
    id: number;
    /**
     * The name of the location to be exported.
     */
    name: string;
}

export interface GetZIARuleLabelsCreatedBy {
    extensions: {[key: string]: string};
    /**
     * The unique identifer for the device group.
     */
    id: number;
    /**
     * The name of the rule label to be exported.
     */
    name: string;
}

export interface GetZIARuleLabelsLastModifiedBy {
    extensions: {[key: string]: string};
    /**
     * The unique identifer for the device group.
     */
    id: number;
    /**
     * The name of the rule label to be exported.
     */
    name: string;
}

export interface GetZIATrafficForwardingGREInternalIPRangeList {
    endIpAddress: string;
    startIpAddress: string;
}

export interface GetZIATrafficForwardingGRETunnelLastModifiedBy {
    id: number;
    name: string;
}

export interface GetZIATrafficForwardingGRETunnelManagedBy {
    id: number;
    name: string;
}

export interface GetZIATrafficForwardingGRETunnelPrimaryDestVip {
    city: string;
    countryCode: string;
    datacenter: string;
    id: number;
    latitude: number;
    longitude: number;
    privateServiceEdge: boolean;
    region: string;
    virtualIp: string;
}

export interface GetZIATrafficForwardingGRETunnelSecondaryDestVip {
    city: string;
    countryCode: string;
    datacenter: string;
    id: number;
    latitude: number;
    longitude: number;
    privateServiceEdge: boolean;
    region: string;
    virtualIp: string;
}

export interface GetZIATrafficForwardingStaticIPLastModifiedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * The unique identifier for the static IP address
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIATrafficForwardingStaticIPManagedBy {
    /**
     * The unique identifier for the static IP address
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIATrafficForwardingVIPRecommendedListList {
    /**
     * (String) Data center information
     */
    datacenter?: string;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id?: number;
    /**
     * (Boolean) Set to true if the virtual IP address (VIP) is a ZIA Private Service Edge
     */
    privateServiceEdge?: boolean;
    /**
     * (String) GRE cluster virtual IP address (VIP)
     */
    virtualIp?: string;
}

export interface GetZIATrafficForwardingVPNCredentialsLocation {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIATrafficForwardingVPNCredentialsManagedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIAURLCategoriesScope {
    /**
     * (List of Object)
     */
    scopeEntities: outputs.GetZIAURLCategoriesScopeScopeEntity[];
    /**
     * (List of Object) Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group. The attribute name is subject to change.
     */
    scopeGroupMemberEntities: outputs.GetZIAURLCategoriesScopeScopeGroupMemberEntity[];
    /**
     * (String) The admin scope type. The attribute name is subject to change. `ORGANIZATION`, `DEPARTMENT`, `LOCATION`, `LOCATION_GROUP`
     */
    type: string;
}

export interface GetZIAURLCategoriesScopeScopeEntity {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL category
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIAURLCategoriesScopeScopeGroupMemberEntity {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL category
     */
    id: number;
    /**
     * (String) The configured name of the entity
     */
    name: string;
}

export interface GetZIAURLCategoriesUrlKeywordCount {
    /**
     * (Number) Count of total keywords with retain parent category.
     */
    retainParentKeywordCount: number;
    /**
     * (Number) Count of URLs with retain parent category.
     */
    retainParentUrlCount: number;
    /**
     * (Number) Total keyword count for the category.
     */
    totalKeywordCount: number;
    /**
     * (Number) Custom URL count for the category.
     */
    totalUrlCount: number;
}

export interface GetZIAURLFilteringRulesDepartment {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesDevice {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesDeviceGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesLabel {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesLastModifiedBy {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesLocation {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesLocationGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesOverrideGroup {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesOverrideUser {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesTimeWindow {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAURLFilteringRulesUser {
    /**
     * (Map of String)
     */
    extensions: {[key: string]: string};
    /**
     * URL Filtering Rule ID
     */
    id: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name: string;
}

export interface GetZIAUserManagementDepartment {
    /**
     * (String) Additional information about the group
     */
    comments: string;
    /**
     * (Boolean) default: `false`
     */
    deleted: boolean;
    /**
     * The ID of the time window resource.
     */
    id: number;
    /**
     * (Number) Unique identfier for the identity provider (IdP)
     */
    idpId: number;
    /**
     * User name. This appears when choosing users for policies.
     */
    name: string;
}

export interface GetZIAUserManagementGroup {
    /**
     * (String) Additional information about the group
     */
    comments: string;
    /**
     * The ID of the time window resource.
     */
    id: number;
    /**
     * (Number) Unique identfier for the identity provider (IdP)
     */
    idpId: number;
    /**
     * User name. This appears when choosing users for policies.
     */
    name: string;
}

export interface ZIAAdminUsersAdminScope {
    /**
     * Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
     */
    scopeEntities: outputs.ZIAAdminUsersAdminScopeScopeEntities;
    /**
     * Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
     */
    scopeGroupMemberEntities: outputs.ZIAAdminUsersAdminScopeScopeGroupMemberEntities;
    /**
     * The admin scope type. The attribute name is subject to change.
     */
    type: string;
}

export interface ZIAAdminUsersAdminScopeScopeEntities {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAAdminUsersAdminScopeScopeGroupMemberEntities {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAAdminUsersRole {
    extensions: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
    isNameL10nTag: boolean;
    /**
     * The configured name of the entity
     */
    name: string;
}

export interface ZIADLPDictionariesExactDataMatchDetail {
    /**
     * The unique identifier for the EDM mapping.
     */
    dictionaryEdmMappingId: number;
    /**
     * The EDM template's primary field.
     */
    primaryField?: number;
    /**
     * The unique identifier for the EDM template (or schema).
     */
    schemaId: number;
    /**
     * The EDM secondary field to match on.
     * - `"MATCHON_NONE"`
     * - `"MATCHON_ANY_1"`
     * - `"MATCHON_ANY_2"`
     * - `"MATCHON_ANY_3"`
     * - `"MATCHON_ANY_4"`
     * - `"MATCHON_ANY_5"`
     * - `"MATCHON_ANY_6"`
     * - `"MATCHON_ANY_7"`
     * - `"MATCHON_ANY_8"`
     * - `"MATCHON_ANY_9"`
     * - `"MATCHON_ANY_10"`
     * - `"MATCHON_ANY_11"`
     * - `"MATCHON_ANY_12"`
     * - `"MATCHON_ANY_13"`
     * - `"MATCHON_ANY_14"`
     * - `"MATCHON_ANY_15"`
     * - `"MATCHON_ALL"`
     */
    secondaryFieldMatchOn?: string;
    /**
     * The EDM template's secondary fields.
     */
    secondaryFields: number[];
}

export interface ZIADLPDictionariesIdmProfileMatchAccuracy {
    /**
     * The IDM template reference.
     */
    adpIdmProfile?: outputs.ZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile;
    /**
     * The IDM template match accuracy.
     * - `"LOW"`
     * - `"MEDIUM"`
     * - `"HEAVY"`
     */
    matchAccuracy?: string;
}

export interface ZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile {
    extensions: {[key: string]: string};
    id: number;
}

export interface ZIADLPDictionariesPattern {
    /**
     * The action applied to a DLP dictionary using patterns. The following values are supported:
     */
    action?: string;
    /**
     * DLP dictionary pattern
     */
    pattern?: string;
}

export interface ZIADLPDictionariesPhrase {
    /**
     * The action applied to a DLP dictionary using patterns. The following values are supported:
     */
    action?: string;
    /**
     * DLP dictionary phrase
     */
    phrase?: string;
}

export interface ZIADLPWebRulesAuditor {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface ZIADLPWebRulesDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesDlpEngines {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesExcludedDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesExcludedGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesExcludedUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesIcapServer {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface ZIADLPWebRulesLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesNotificationTemplate {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: number;
}

export interface ZIADLPWebRulesTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesUrlCategories {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIADLPWebRulesUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringNetworkServicesDestTcpPort {
    end?: number;
    start?: number;
}

export interface ZIAFirewallFilteringNetworkServicesDestUdpPort {
    end?: number;
    start?: number;
}

export interface ZIAFirewallFilteringNetworkServicesSrcTcpPort {
    end?: number;
    start?: number;
}

export interface ZIAFirewallFilteringNetworkServicesSrcUdpPort {
    end?: number;
    start?: number;
}

export interface ZIAFirewallFilteringRuleAppServiceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleAppServices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleDestIpGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleLastModifiedBy {
    extensions?: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id?: number;
}

export interface ZIAFirewallFilteringRuleLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleNwApplicationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleNwServiceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleNwServices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleSrcIpGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringRuleUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAFirewallFilteringServiceGroupsService {
    ids: number[];
}

export interface ZIALocationManagementVpnCredential {
    comments: string;
    fqdn: string;
    /**
     * VPN credential resource id. The value is required if `ipAddresses` are not defined.
     */
    id: number;
    ipAddress: string;
    preSharedKey?: string;
    type: string;
}

export interface ZIARuleLabelsCreatedBy {
    extensions?: {[key: string]: string};
    id: number;
    /**
     * The name of the devices to be created.
     */
    name: string;
}

export interface ZIARuleLabelsLastModifiedBy {
    extensions?: {[key: string]: string};
    id: number;
    /**
     * The name of the devices to be created.
     */
    name: string;
}

export interface ZIATrafficForwardingGRETunnelLastModifiedBy {
    extensions: {[key: string]: string};
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id: number;
    name: string;
}

export interface ZIATrafficForwardingGRETunnelPrimaryDestVip {
    datacenter: string;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id: number;
    privateServiceEdge: boolean;
    /**
     * GRE cluster virtual IP address (VIP)
     */
    virtualIp: string;
}

export interface ZIATrafficForwardingGRETunnelSecondaryDestVip {
    datacenter: string;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id: number;
    privateServiceEdge: boolean;
    /**
     * GRE cluster virtual IP address (VIP)
     */
    virtualIp: string;
}

export interface ZIATrafficForwardingStaticIPLastModifiedBy {
    extensions?: {[key: string]: string};
    id?: number;
    name?: string;
}

export interface ZIATrafficForwardingStaticIPManagedBy {
    extensions?: {[key: string]: string};
    id?: number;
    name?: string;
}

export interface ZIAURLCategoriesScope {
    scopeEntities: outputs.ZIAURLCategoriesScopeScopeEntities;
    /**
     * Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group. The attribute name is subject to change.
     */
    scopeGroupMemberEntities: outputs.ZIAURLCategoriesScopeScopeGroupMemberEntities;
    /**
     * Type of the custom categories. `URL_CATEGORY`, `TLD_CATEGORY`, `ALL`
     */
    type?: string;
}

export interface ZIAURLCategoriesScopeScopeEntities {
    ids: number[];
}

export interface ZIAURLCategoriesScopeScopeGroupMemberEntities {
    ids: number[];
}

export interface ZIAURLCategoriesUrlKeywordCounts {
    /**
     * Count of total keywords with retain parent category.
     */
    retainParentKeywordCount: number;
    /**
     * Count of URLs with retain parent category.
     */
    retainParentUrlCount: number;
    /**
     * Total keyword count for the category.
     */
    totalKeywordCount: number;
    /**
     * Custom URL count for the category.
     */
    totalUrlCount: number;
}

export interface ZIAURLFilteringRulesDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesDeviceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesDevices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesLastModifiedBy {
    extensions?: {[key: string]: string};
    /**
     * Identifier that uniquely identifies an entity
     */
    id?: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name: string;
}

export interface ZIAURLFilteringRulesLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesOverrideGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesOverrideUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAURLFilteringRulesUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: number[];
}

export interface ZIAUserManagementDepartment {
    comments: string;
    deleted: boolean;
    /**
     * Department ID
     */
    id?: number;
    idpId: number;
    /**
     * User name. This appears when choosing users for policies.
     */
    name: string;
}

export interface ZIAUserManagementGroups {
    /**
     * Department ID
     */
    ids: number[];
}
