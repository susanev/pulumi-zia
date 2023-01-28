// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

/**
 * Use the **zia_url_filtering_rules** data source to get information about a URL filtering rule information for the specified `Name`.
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.getZIAURLFilteringRules({
 *     name: "Example",
 * });
 * ```
 */
export function getZIAURLFilteringRules(args?: GetZIAURLFilteringRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetZIAURLFilteringRulesResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIAURLFilteringRules:getZIAURLFilteringRules", {
        "deviceTrustLevels": args.deviceTrustLevels,
        "id": args.id,
        "name": args.name,
        "order": args.order,
        "userAgentTypes": args.userAgentTypes,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIAURLFilteringRules.
 */
export interface GetZIAURLFilteringRulesArgs {
    deviceTrustLevels?: string[];
    /**
     * URL Filtering Rule ID
     */
    id?: number;
    /**
     * Name of the URL Filtering policy rule
     */
    name?: string;
    /**
     * (Number) Order of execution of rule with respect to other URL Filtering rules
     */
    order?: number;
    userAgentTypes?: string[];
}

/**
 * A collection of values returned by getZIAURLFilteringRules.
 */
export interface GetZIAURLFilteringRulesResult {
    /**
     * (String) Action taken when traffic matches rule criteria. Supported values: `ANY`, `NONE`, `BLOCK`, `CAUTION`, `ALLOW`, `ICAP_RESPONSE`
     */
    readonly action: string;
    /**
     * (String) When set to true, a `BLOCK` action triggered by the rule could be overridden. If true and both overrideGroup and overrideUsers are not set, the `BLOCK` triggered by this rule could be overridden for any users. If block)Override is not set, `BLOCK` action cannot be overridden.
     */
    readonly blockOverride: boolean;
    readonly cbiProfileId: number;
    readonly ciparule: boolean;
    /**
     * (List of Object) The departments to which the Firewall Filtering policy rule applies
     */
    readonly departments: outputs.GetZIAURLFilteringRulesDepartment[];
    /**
     * (String) Additional information about the rule
     */
    readonly description: string;
    readonly deviceGroups: outputs.GetZIAURLFilteringRulesDeviceGroup[];
    readonly deviceTrustLevels?: string[];
    readonly devices: outputs.GetZIAURLFilteringRulesDevice[];
    /**
     * (String) URL of end user notification page to be displayed when the rule is matched. Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
     */
    readonly endUserNotificationUrl: string;
    /**
     * (String) Enforce a set a validity time period for the URL Filtering rule.
     */
    readonly enforceTimeValidity: boolean;
    /**
     * (List of Object) The groups to which the Firewall Filtering policy rule applies
     */
    readonly groups: outputs.GetZIAURLFilteringRulesGroup[];
    /**
     * (Number) Identifier that uniquely identifies an entity
     */
    readonly id: number;
    readonly labels: outputs.GetZIAURLFilteringRulesLabel[];
    readonly lastModifiedBies: outputs.GetZIAURLFilteringRulesLastModifiedBy[];
    /**
     * (Number) When the rule was last modified
     */
    readonly lastModifiedTime: number;
    /**
     * (List of Object) The location groups to which the Firewall Filtering policy rule applies
     */
    readonly locationGroups: outputs.GetZIAURLFilteringRulesLocationGroup[];
    /**
     * (List of Object) The locations to which the Firewall Filtering policy rule applies
     */
    readonly locations: outputs.GetZIAURLFilteringRulesLocation[];
    /**
     * (String) The configured name of the entity
     */
    readonly name: string;
    /**
     * (Number) Order of execution of rule with respect to other URL Filtering rules
     */
    readonly order: number;
    /**
     * (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any group.
     */
    readonly overrideGroups: outputs.GetZIAURLFilteringRulesOverrideGroup[];
    /**
     * (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any user.
     */
    readonly overrideUsers: outputs.GetZIAURLFilteringRulesOverrideUser[];
    /**
     * (List of Object) Protocol criteria. Supported values: `SMRULEF_ZPA_BROKERS_RULE`, `ANY_RULE`, `TCP_RULE`, `UDP_RULE`, `DOHTTPS_RULE`, `TUNNELSSL_RULE`, `HTTP_PROXY`, `FOHTTP_RULE`, `FTP_RULE`, `HTTPS_RULE`, `HTTP_RULE`, `SSL_RULE`, `TUNNEL_RULE`.
     */
    readonly protocols: string[];
    /**
     * (String) Admin rank of the admin who creates this rule
     */
    readonly rank: number;
    /**
     * (String) Request method for which the rule must be applied. If not set, rule will be applied to all methods
     */
    readonly requestMethods: string[];
    /**
     * (String) Size quota in KB beyond which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
     */
    readonly sizeQuota: number;
    /**
     * (String) Rule State
     */
    readonly state: string;
    /**
     * (String) Time quota in minutes, after which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
     */
    readonly timeQuota: number;
    /**
     * (List of Object) The time interval in which the Firewall Filtering policy rule applies
     */
    readonly timeWindows: outputs.GetZIAURLFilteringRulesTimeWindow[];
    /**
     * (String) List of URL categories for which rule must be applied
     */
    readonly urlCategories: string[];
    readonly userAgentTypes?: string[];
    /**
     * (List of Object) The users to which the Firewall Filtering policy rule applies
     */
    readonly users: outputs.GetZIAURLFilteringRulesUser[];
    /**
     * (Number) If enforceTimeValidity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
     */
    readonly validityEndTime: number;
    /**
     * (Number) If enforceTimeValidity is set to true, the URL Filtering rule will be valid starting on this date and time.
     */
    readonly validityStartTime: number;
    /**
     * (Number) If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID.
     */
    readonly validityTimeZoneId: string;
}
/**
 * Use the **zia_url_filtering_rules** data source to get information about a URL filtering rule information for the specified `Name`.
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.getZIAURLFilteringRules({
 *     name: "Example",
 * });
 * ```
 */
export function getZIAURLFilteringRulesOutput(args?: GetZIAURLFilteringRulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIAURLFilteringRulesResult> {
    return pulumi.output(args).apply((a: any) => getZIAURLFilteringRules(a, opts))
}

/**
 * A collection of arguments for invoking getZIAURLFilteringRules.
 */
export interface GetZIAURLFilteringRulesOutputArgs {
    deviceTrustLevels?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * URL Filtering Rule ID
     */
    id?: pulumi.Input<number>;
    /**
     * Name of the URL Filtering policy rule
     */
    name?: pulumi.Input<string>;
    /**
     * (Number) Order of execution of rule with respect to other URL Filtering rules
     */
    order?: pulumi.Input<number>;
    userAgentTypes?: pulumi.Input<pulumi.Input<string>[]>;
}