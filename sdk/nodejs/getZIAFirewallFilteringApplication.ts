// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

/**
 * Use the **zia_firewall_filtering_network_application** data source to get information about a network application available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network application rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const apns = zia.getZIAFirewallFilteringApplication({
 *     id: "APNS",
 *     locale: "en-US",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const dict = zia.getZIAFirewallFilteringApplication({
 *     id: "DICT",
 * });
 * ```
 */
export function getZIAFirewallFilteringApplication(args?: GetZIAFirewallFilteringApplicationArgs, opts?: pulumi.InvokeOptions): Promise<GetZIAFirewallFilteringApplicationResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIAFirewallFilteringApplication:getZIAFirewallFilteringApplication", {
        "id": args.id,
        "locale": args.locale,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIAFirewallFilteringApplication.
 */
export interface GetZIAFirewallFilteringApplicationArgs {
    /**
     * The name of the ip source group to be exported.
     */
    id?: string;
    locale?: string;
}

/**
 * A collection of values returned by getZIAFirewallFilteringApplication.
 */
export interface GetZIAFirewallFilteringApplicationResult {
    /**
     * (Boolean)
     */
    readonly deprecated: boolean;
    /**
     * (String)
     */
    readonly description: string;
    readonly id?: string;
    readonly locale?: string;
    /**
     * (String)
     */
    readonly parentCategory: string;
}
/**
 * Use the **zia_firewall_filtering_network_application** data source to get information about a network application available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network application rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const apns = zia.getZIAFirewallFilteringApplication({
 *     id: "APNS",
 *     locale: "en-US",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const dict = zia.getZIAFirewallFilteringApplication({
 *     id: "DICT",
 * });
 * ```
 */
export function getZIAFirewallFilteringApplicationOutput(args?: GetZIAFirewallFilteringApplicationOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIAFirewallFilteringApplicationResult> {
    return pulumi.output(args).apply((a: any) => getZIAFirewallFilteringApplication(a, opts))
}

/**
 * A collection of arguments for invoking getZIAFirewallFilteringApplication.
 */
export interface GetZIAFirewallFilteringApplicationOutputArgs {
    /**
     * The name of the ip source group to be exported.
     */
    id?: pulumi.Input<string>;
    locale?: pulumi.Input<string>;
}
