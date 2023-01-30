// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * Use the **zia_firewall_filtering_rule** data source to get information about a cloud firewall rule available in the Zscaler Internet Access cloud firewall.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.Firewall.getFirewallFilteringRule({
 *     name: "Office 365 One Click Rule",
 * });
 * ```
 */
export function getFirewallFilteringRule(args?: GetFirewallFilteringRuleArgs, opts?: pulumi.InvokeOptions): Promise<GetFirewallFilteringRuleResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:Firewall/getFirewallFilteringRule:getFirewallFilteringRule", {
        "action": args.action,
        "description": args.description,
        "id": args.id,
        "lastModifiedTime": args.lastModifiedTime,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getFirewallFilteringRule.
 */
export interface GetFirewallFilteringRuleArgs {
    /**
     * (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
     */
    action?: string;
    /**
     * (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
     */
    description?: string;
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id?: number;
    /**
     * (Number)
     */
    lastModifiedTime?: number;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name?: string;
    /**
     * (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
     */
    state?: string;
}

/**
 * A collection of values returned by getFirewallFilteringRule.
 */
export interface GetFirewallFilteringRuleResult {
    /**
     * (String)
     */
    readonly accessControl: string;
    /**
     * (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
     */
    readonly action?: string;
    /**
     * Application service groups on which this rule is applied
     */
    readonly appServiceGroups: outputs.Firewall.GetFirewallFilteringRuleAppServiceGroup[];
    /**
     * Application services on which this rule is applied
     */
    readonly appServices: outputs.Firewall.GetFirewallFilteringRuleAppService[];
    /**
     * (Boolean)
     */
    readonly defaultRule: boolean;
    /**
     * (Optional) Apply to any number of departments When not used it implies `Any` to apply the rule to all departments.
     */
    readonly departments: outputs.Firewall.GetFirewallFilteringRuleDepartment[];
    /**
     * (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
     */
    readonly description?: string;
    /**
     * ** - (Optional) -  IP addresses and fully qualified domain names (FQDNs), if the domain has multiple destination IP addresses or if its IP addresses may change. For IP addresses, you can enter individual IP addresses, subnets, or address ranges. If adding multiple items, hit Enter after each entry.
     */
    readonly destAddresses: string[];
    /**
     * ** - (Optional) Identify destinations based on the location of a server, select Any to apply the rule to all countries or select the countries to which you want to control traffic.
     */
    readonly destCountries: string[];
    /**
     * ** - (Optional) identify destinations based on the URL category of the domain, select Any to apply the rule to all categories or select the specific categories you want to control.
     */
    readonly destIpCategories: string[];
    /**
     * ** - (Optional) Any number of destination IP address groups that you want to control with this rule.
     */
    readonly destIpGroups: string[];
    /**
     * (Boolean)
     */
    readonly enableFullLogging: boolean;
    /**
     * (Optional) You can manually select up to `8` groups. When not used it implies `Any` to apply the rule to all groups.
     */
    readonly groups: outputs.Firewall.GetFirewallFilteringRuleGroup[];
    /**
     * (Number) The ID of this resource.
     */
    readonly id: number;
    /**
     * Labels that are applicable to the rule.
     */
    readonly labels: outputs.Firewall.GetFirewallFilteringRuleLabel[];
    readonly lastModifiedBies: outputs.Firewall.GetFirewallFilteringRuleLastModifiedBy[];
    /**
     * (Number)
     */
    readonly lastModifiedTime?: number;
    /**
     * (Optional) You can manually select up to `32` location groups. When not used it implies `Any` to apply the rule to all location groups.
     */
    readonly locationGroups: outputs.Firewall.GetFirewallFilteringRuleLocationGroup[];
    /**
     * (Optional) You can manually select up to `8` locations. When not used it implies `Any` to apply the rule to all groups.
     */
    readonly locations: outputs.Firewall.GetFirewallFilteringRuleLocation[];
    /**
     * (String) The configured name of the entity
     */
    readonly name: string;
    /**
     * (Optional) Any number of application groups that you want to control with this rule. The service provides predefined applications that you can group, but not modify
     */
    readonly nwApplicationGroups: outputs.Firewall.GetFirewallFilteringRuleNwApplicationGroup[];
    /**
     * (Optional) When not used it applies the rule to all applications. The service provides predefined applications, which you can group, but not modify.
     */
    readonly nwApplications: string[];
    /**
     * (Optional) Any number of predefined or custom network service groups to which the rule applies.
     */
    readonly nwServiceGroups: outputs.Firewall.GetFirewallFilteringRuleNwServiceGroup[];
    /**
     * (Optional) When not used it applies the rule to all network services or you can select specific network services. The Zscaler firewall has predefined services and you can configure up to `1,024` additional custom services.
     */
    readonly nwServices: outputs.Firewall.GetFirewallFilteringRuleNwService[];
    /**
     * (Required) Policy rules are evaluated in ascending numerical order (Rule 1 before Rule 2, and so on), and the Rule Order reflects this rule's place in the order.
     */
    readonly order: number;
    /**
     * (Boolean)
     */
    readonly predefined: boolean;
    /**
     * (Optional) By default, the admin ranking is disabled. To use this feature, you must enable admin rank. The default value is `7`.
     */
    readonly rank: number;
    /**
     * (Optional) Any number of source IP address groups that you want to control with this rule.
     */
    readonly srcIpGroups: string[];
    /**
     * (Optional) You can enter individual IP addresses, subnets, or address ranges.
     */
    readonly srcIps: string[];
    /**
     * (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
     */
    readonly state?: string;
    /**
     * (Optional) You can manually select up to `2` time intervals. When not used it implies `always` to apply the rule to all time intervals.
     */
    readonly timeWindows: outputs.Firewall.GetFirewallFilteringRuleTimeWindow[];
    /**
     * (Optional) You can manually select up to `4` general and/or special users. When not used it implies `Any` to apply the rule to all users.
     */
    readonly users: outputs.Firewall.GetFirewallFilteringRuleUser[];
}
/**
 * Use the **zia_firewall_filtering_rule** data source to get information about a cloud firewall rule available in the Zscaler Internet Access cloud firewall.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.Firewall.getFirewallFilteringRule({
 *     name: "Office 365 One Click Rule",
 * });
 * ```
 */
export function getFirewallFilteringRuleOutput(args?: GetFirewallFilteringRuleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFirewallFilteringRuleResult> {
    return pulumi.output(args).apply((a: any) => getFirewallFilteringRule(a, opts))
}

/**
 * A collection of arguments for invoking getFirewallFilteringRule.
 */
export interface GetFirewallFilteringRuleOutputArgs {
    /**
     * (Optional) Choose the action of the service when packets match the rule. The following actions are accepted: `ALLOW`, `BLOCK_DROP`, `BLOCK_RESET`, `BLOCK_ICMP`, `EVAL_NWAPP`
     */
    action?: pulumi.Input<string>;
    /**
     * (Optional) Enter additional notes or information. The description cannot exceed 10,240 characters.
     */
    description?: pulumi.Input<string>;
    /**
     * Unique identifier for the Firewall Filtering policy rule
     */
    id?: pulumi.Input<number>;
    /**
     * (Number)
     */
    lastModifiedTime?: pulumi.Input<number>;
    /**
     * Name of the Firewall Filtering policy rule
     */
    name?: pulumi.Input<string>;
    /**
     * (Optional) An enabled rule is actively enforced. A disabled rule is not actively enforced but does not lose its place in the Rule Order. The service skips it and moves to the next rule.
     */
    state?: pulumi.Input<string>;
}