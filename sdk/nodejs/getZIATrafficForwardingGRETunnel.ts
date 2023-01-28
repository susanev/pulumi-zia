// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getZIATrafficForwardingGRETunnel(args?: GetZIATrafficForwardingGRETunnelArgs, opts?: pulumi.InvokeOptions): Promise<GetZIATrafficForwardingGRETunnelResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIATrafficForwardingGRETunnel:getZIATrafficForwardingGRETunnel", {
        "id": args.id,
        "sourceIp": args.sourceIp,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIATrafficForwardingGRETunnel.
 */
export interface GetZIATrafficForwardingGRETunnelArgs {
    id?: number;
    sourceIp?: string;
}

/**
 * A collection of values returned by getZIATrafficForwardingGRETunnel.
 */
export interface GetZIATrafficForwardingGRETunnelResult {
    readonly comment: string;
    readonly id?: number;
    readonly internalIpRange: string;
    readonly ipUnnumbered: boolean;
    readonly lastModificationTime: number;
    readonly lastModifiedBies: outputs.GetZIATrafficForwardingGRETunnelLastModifiedBy[];
    readonly managedBies: outputs.GetZIATrafficForwardingGRETunnelManagedBy[];
    readonly primaryDestVips: outputs.GetZIATrafficForwardingGRETunnelPrimaryDestVip[];
    readonly secondaryDestVips: outputs.GetZIATrafficForwardingGRETunnelSecondaryDestVip[];
    readonly sourceIp?: string;
    readonly withinCountry: boolean;
}
export function getZIATrafficForwardingGRETunnelOutput(args?: GetZIATrafficForwardingGRETunnelOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIATrafficForwardingGRETunnelResult> {
    return pulumi.output(args).apply((a: any) => getZIATrafficForwardingGRETunnel(a, opts))
}

/**
 * A collection of arguments for invoking getZIATrafficForwardingGRETunnel.
 */
export interface GetZIATrafficForwardingGRETunnelOutputArgs {
    id?: pulumi.Input<number>;
    sourceIp?: pulumi.Input<string>;
}