// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";

export interface GetZIALocationGroupsDynamicLocationGroupCriteria {
    /**
     * (Block List)
     */
    cities?: inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCity[];
    /**
     * (List of String) One or more countries from a predefined set
     */
    countries?: string[];
    /**
     * (Boolean) Enable Bandwidth Control. When set to true, Bandwidth Control is enabled for the location.
     */
    enableBandwidthControl?: boolean;
    /**
     * (Boolean) Enable Caution. When set to true, a caution notifcation is enabled for the location.
     */
    enableCaution?: boolean;
    /**
     * (Boolean) Enable `XFF` Forwarding. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header.
     */
    enableXffForwarding?: boolean;
    /**
     * (Boolean) Enable AUP. When set to true, AUP is enabled for the location.
     */
    enforceAup?: boolean;
    /**
     * (Boolean) Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled.
     */
    enforceAuthentication?: boolean;
    /**
     * (Boolean) Enable Firewall. When set to true, Firewall is enabled for the location.
     */
    enforceFirewallControl?: boolean;
    /**
     * (Block List)
     */
    managedBies?: inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedBy[];
    /**
     * Location group name
     */
    names?: inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaName[];
    /**
     * (List of String) One or more location profiles from a predefined set
     */
    profiles?: string[];
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaArgs {
    /**
     * (Block List)
     */
    cities?: pulumi.Input<pulumi.Input<inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCityArgs>[]>;
    /**
     * (List of String) One or more countries from a predefined set
     */
    countries?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Boolean) Enable Bandwidth Control. When set to true, Bandwidth Control is enabled for the location.
     */
    enableBandwidthControl?: pulumi.Input<boolean>;
    /**
     * (Boolean) Enable Caution. When set to true, a caution notifcation is enabled for the location.
     */
    enableCaution?: pulumi.Input<boolean>;
    /**
     * (Boolean) Enable `XFF` Forwarding. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header.
     */
    enableXffForwarding?: pulumi.Input<boolean>;
    /**
     * (Boolean) Enable AUP. When set to true, AUP is enabled for the location.
     */
    enforceAup?: pulumi.Input<boolean>;
    /**
     * (Boolean) Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled.
     */
    enforceAuthentication?: pulumi.Input<boolean>;
    /**
     * (Boolean) Enable Firewall. When set to true, Firewall is enabled for the location.
     */
    enforceFirewallControl?: pulumi.Input<boolean>;
    /**
     * (Block List)
     */
    managedBies?: pulumi.Input<pulumi.Input<inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs>[]>;
    /**
     * Location group name
     */
    names?: pulumi.Input<pulumi.Input<inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaNameArgs>[]>;
    /**
     * (List of String) One or more location profiles from a predefined set
     */
    profiles?: pulumi.Input<pulumi.Input<string>[]>;
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

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaCityArgs {
    /**
     * (String) String value to be matched or partially matched
     */
    matchString?: pulumi.Input<string>;
    /**
     * (String) Operator that performs match action
     */
    matchType?: pulumi.Input<string>;
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaManagedBy {
    /**
     * (Map of String)
     */
    extensions?: {[key: string]: string};
    /**
     * Unique identifier for the location group
     */
    id?: number;
    /**
     * Location group name
     */
    name?: string;
}

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs {
    /**
     * (Map of String)
     */
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Unique identifier for the location group
     */
    id?: pulumi.Input<number>;
    /**
     * Location group name
     */
    name?: pulumi.Input<string>;
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

export interface GetZIALocationGroupsDynamicLocationGroupCriteriaNameArgs {
    /**
     * (String) String value to be matched or partially matched
     */
    matchString?: pulumi.Input<string>;
    /**
     * (String) Operator that performs match action
     */
    matchType?: pulumi.Input<string>;
}

export interface ZIAAdminUsersAdminScope {
    /**
     * Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
     */
    scopeEntities?: pulumi.Input<inputs.ZIAAdminUsersAdminScopeScopeEntities>;
    /**
     * Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
     */
    scopeGroupMemberEntities?: pulumi.Input<inputs.ZIAAdminUsersAdminScopeScopeGroupMemberEntities>;
    /**
     * The admin scope type. The attribute name is subject to change.
     */
    type?: pulumi.Input<string>;
}

export interface ZIAAdminUsersAdminScopeScopeEntities {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAAdminUsersAdminScopeScopeGroupMemberEntities {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAAdminUsersRole {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Identifier that uniquely identifies an entity
     */
    id?: pulumi.Input<number>;
    isNameL10nTag?: pulumi.Input<boolean>;
    /**
     * The configured name of the entity
     */
    name?: pulumi.Input<string>;
}

export interface ZIADLPDictionariesExactDataMatchDetail {
    /**
     * The unique identifier for the EDM mapping.
     */
    dictionaryEdmMappingId?: pulumi.Input<number>;
    /**
     * The EDM template's primary field.
     */
    primaryField?: pulumi.Input<number>;
    /**
     * The unique identifier for the EDM template (or schema).
     */
    schemaId?: pulumi.Input<number>;
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
    secondaryFieldMatchOn?: pulumi.Input<string>;
    /**
     * The EDM template's secondary fields.
     */
    secondaryFields?: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPDictionariesIdmProfileMatchAccuracy {
    /**
     * The IDM template reference.
     */
    adpIdmProfile?: pulumi.Input<inputs.ZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile>;
    /**
     * The IDM template match accuracy.
     * - `"LOW"`
     * - `"MEDIUM"`
     * - `"HEAVY"`
     */
    matchAccuracy?: pulumi.Input<string>;
}

export interface ZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    id?: pulumi.Input<number>;
}

export interface ZIADLPDictionariesPattern {
    /**
     * The action applied to a DLP dictionary using patterns. The following values are supported:
     */
    action?: pulumi.Input<string>;
    /**
     * DLP dictionary pattern
     */
    pattern?: pulumi.Input<string>;
}

export interface ZIADLPDictionariesPhrase {
    /**
     * The action applied to a DLP dictionary using patterns. The following values are supported:
     */
    action?: pulumi.Input<string>;
    /**
     * DLP dictionary phrase
     */
    phrase?: pulumi.Input<string>;
}

export interface ZIADLPWebRulesAuditor {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: pulumi.Input<number>;
}

export interface ZIADLPWebRulesDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesDlpEngines {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesExcludedDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesExcludedGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesExcludedUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesIcapServer {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: pulumi.Input<number>;
}

export interface ZIADLPWebRulesLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesNotificationTemplate {
    /**
     * Identifier that uniquely identifies an entity
     */
    id: pulumi.Input<number>;
}

export interface ZIADLPWebRulesTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesUrlCategories {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIADLPWebRulesUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringNetworkServicesDestTcpPort {
    end?: pulumi.Input<number>;
    start?: pulumi.Input<number>;
}

export interface ZIAFirewallFilteringNetworkServicesDestUdpPort {
    end?: pulumi.Input<number>;
    start?: pulumi.Input<number>;
}

export interface ZIAFirewallFilteringNetworkServicesSrcTcpPort {
    end?: pulumi.Input<number>;
    start?: pulumi.Input<number>;
}

export interface ZIAFirewallFilteringNetworkServicesSrcUdpPort {
    end?: pulumi.Input<number>;
    start?: pulumi.Input<number>;
}

export interface ZIAFirewallFilteringRuleAppServiceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleAppServices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleDestIpGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleLastModifiedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Identifier that uniquely identifies an entity
     */
    id?: pulumi.Input<number>;
}

export interface ZIAFirewallFilteringRuleLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleNwApplicationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleNwServiceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleNwServices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleSrcIpGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringRuleUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAFirewallFilteringServiceGroupsService {
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIALocationManagementVpnCredential {
    comments?: pulumi.Input<string>;
    fqdn?: pulumi.Input<string>;
    /**
     * VPN credential resource id. The value is required if `ipAddresses` are not defined.
     */
    id?: pulumi.Input<number>;
    ipAddress?: pulumi.Input<string>;
    preSharedKey?: pulumi.Input<string>;
    type?: pulumi.Input<string>;
}

export interface ZIARuleLabelsCreatedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    id?: pulumi.Input<number>;
    /**
     * The name of the devices to be created.
     */
    name?: pulumi.Input<string>;
}

export interface ZIARuleLabelsLastModifiedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    id?: pulumi.Input<number>;
    /**
     * The name of the devices to be created.
     */
    name?: pulumi.Input<string>;
}

export interface ZIATrafficForwardingGRETunnelLastModifiedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id?: pulumi.Input<number>;
    name?: pulumi.Input<string>;
}

export interface ZIATrafficForwardingGRETunnelPrimaryDestVip {
    datacenter?: pulumi.Input<string>;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id?: pulumi.Input<number>;
    privateServiceEdge?: pulumi.Input<boolean>;
    /**
     * GRE cluster virtual IP address (VIP)
     */
    virtualIp?: pulumi.Input<string>;
}

export interface ZIATrafficForwardingGRETunnelSecondaryDestVip {
    datacenter?: pulumi.Input<string>;
    /**
     * Unique identifer of the GRE virtual IP address (VIP)
     */
    id?: pulumi.Input<number>;
    privateServiceEdge?: pulumi.Input<boolean>;
    /**
     * GRE cluster virtual IP address (VIP)
     */
    virtualIp?: pulumi.Input<string>;
}

export interface ZIATrafficForwardingStaticIPLastModifiedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    id?: pulumi.Input<number>;
    name?: pulumi.Input<string>;
}

export interface ZIATrafficForwardingStaticIPManagedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    id?: pulumi.Input<number>;
    name?: pulumi.Input<string>;
}

export interface ZIAURLCategoriesScope {
    scopeEntities?: pulumi.Input<inputs.ZIAURLCategoriesScopeScopeEntities>;
    /**
     * Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group. The attribute name is subject to change.
     */
    scopeGroupMemberEntities?: pulumi.Input<inputs.ZIAURLCategoriesScopeScopeGroupMemberEntities>;
    /**
     * Type of the custom categories. `URL_CATEGORY`, `TLD_CATEGORY`, `ALL`
     */
    type?: pulumi.Input<string>;
}

export interface ZIAURLCategoriesScopeScopeEntities {
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLCategoriesScopeScopeGroupMemberEntities {
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLCategoriesUrlKeywordCounts {
    /**
     * Count of total keywords with retain parent category.
     */
    retainParentKeywordCount?: pulumi.Input<number>;
    /**
     * Count of URLs with retain parent category.
     */
    retainParentUrlCount?: pulumi.Input<number>;
    /**
     * Total keyword count for the category.
     */
    totalKeywordCount?: pulumi.Input<number>;
    /**
     * Custom URL count for the category.
     */
    totalUrlCount?: pulumi.Input<number>;
}

export interface ZIAURLFilteringRulesDepartments {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesDeviceGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesDevices {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesLabels {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesLastModifiedBy {
    extensions?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Identifier that uniquely identifies an entity
     */
    id?: pulumi.Input<number>;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name?: pulumi.Input<string>;
}

export interface ZIAURLFilteringRulesLocationGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesLocations {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesOverrideGroups {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesOverrideUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesTimeWindows {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAURLFilteringRulesUsers {
    /**
     * Identifier that uniquely identifies an entity
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}

export interface ZIAUserManagementDepartment {
    comments?: pulumi.Input<string>;
    deleted?: pulumi.Input<boolean>;
    /**
     * Department ID
     */
    id?: pulumi.Input<number>;
    idpId?: pulumi.Input<number>;
    /**
     * User name. This appears when choosing users for policies.
     */
    name?: pulumi.Input<string>;
}

export interface ZIAUserManagementGroups {
    /**
     * Department ID
     */
    ids: pulumi.Input<pulumi.Input<number>[]>;
}
