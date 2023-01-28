// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

/**
 * The **zia_firewall_filtering_network_service** data source to get information about a network service available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network service rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.getZIAFirewallFilteringNetworkServices({
 *     name: "ICMP_ANY",
 * });
 * ```
 */
export function getZIAFirewallFilteringNetworkServices(args?: GetZIAFirewallFilteringNetworkServicesArgs, opts?: pulumi.InvokeOptions): Promise<GetZIAFirewallFilteringNetworkServicesResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIAFirewallFilteringNetworkServices:getZIAFirewallFilteringNetworkServices", {
        "id": args.id,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIAFirewallFilteringNetworkServices.
 */
export interface GetZIAFirewallFilteringNetworkServicesArgs {
    /**
     * The ID of the application layer service to be exported.
     */
    id?: number;
    /**
     * Name of the application layer service that you want to control. It can include any character and spaces.
     */
    name?: string;
}

/**
 * A collection of values returned by getZIAFirewallFilteringNetworkServices.
 */
export interface GetZIAFirewallFilteringNetworkServicesResult {
    /**
     * (String) (Optional) Enter additional notes or information. The description cannot exceed 10240 characters.
     */
    readonly description: string;
    /**
     * (Required) The TCP destination port number (example: 50) or port number range (example: 1000-1050), if any, that is used by the network service.
     */
    readonly destTcpPorts: outputs.GetZIAFirewallFilteringNetworkServicesDestTcpPort[];
    /**
     * The UDP source port number (example: 50) or port number range (example: 1000-1050), if any, that is used by the network service.
     */
    readonly destUdpPorts: outputs.GetZIAFirewallFilteringNetworkServicesDestUdpPort[];
    readonly id: number;
    /**
     * (Bool) - Default: false
     */
    readonly isNameL10nTag: boolean;
    readonly name: string;
    /**
     * (Optional) The TCP source port number (example: 50) or port number range (example: 1000-1050), if any, that is used by the network service
     */
    readonly srcTcpPorts: outputs.GetZIAFirewallFilteringNetworkServicesSrcTcpPort[];
    /**
     * The UDP source port number (example: 50) or port number range (example: 1000-1050), if any, that is used by the network service.
     */
    readonly srcUdpPorts: outputs.GetZIAFirewallFilteringNetworkServicesSrcUdpPort[];
    readonly tag: string;
    /**
     * (String) - Supported values are: `STANDARD`, `PREDEFINED` and `CUSTOM`
     */
    readonly type: string;
}
/**
 * The **zia_firewall_filtering_network_service** data source to get information about a network service available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering network service rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const example = zia.getZIAFirewallFilteringNetworkServices({
 *     name: "ICMP_ANY",
 * });
 * ```
 */
export function getZIAFirewallFilteringNetworkServicesOutput(args?: GetZIAFirewallFilteringNetworkServicesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIAFirewallFilteringNetworkServicesResult> {
    return pulumi.output(args).apply((a: any) => getZIAFirewallFilteringNetworkServices(a, opts))
}

/**
 * A collection of arguments for invoking getZIAFirewallFilteringNetworkServices.
 */
export interface GetZIAFirewallFilteringNetworkServicesOutputArgs {
    /**
     * The ID of the application layer service to be exported.
     */
    id?: pulumi.Input<number>;
    /**
     * Name of the application layer service that you want to control. It can include any character and spaces.
     */
    name?: pulumi.Input<string>;
}
