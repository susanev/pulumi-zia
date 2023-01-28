// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getZIATrafficForwardingGREInternalIPRange(args?: GetZIATrafficForwardingGREInternalIPRangeArgs, opts?: pulumi.InvokeOptions): Promise<GetZIATrafficForwardingGREInternalIPRangeResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIATrafficForwardingGREInternalIPRange:getZIATrafficForwardingGREInternalIPRange", {
        "requiredCount": args.requiredCount,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIATrafficForwardingGREInternalIPRange.
 */
export interface GetZIATrafficForwardingGREInternalIPRangeArgs {
    requiredCount?: number;
}

/**
 * A collection of values returned by getZIATrafficForwardingGREInternalIPRange.
 */
export interface GetZIATrafficForwardingGREInternalIPRangeResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly lists: outputs.GetZIATrafficForwardingGREInternalIPRangeList[];
    readonly requiredCount?: number;
}
export function getZIATrafficForwardingGREInternalIPRangeOutput(args?: GetZIATrafficForwardingGREInternalIPRangeOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIATrafficForwardingGREInternalIPRangeResult> {
    return pulumi.output(args).apply((a: any) => getZIATrafficForwardingGREInternalIPRange(a, opts))
}

/**
 * A collection of arguments for invoking getZIATrafficForwardingGREInternalIPRange.
 */
export interface GetZIATrafficForwardingGREInternalIPRangeOutputArgs {
    requiredCount?: pulumi.Input<number>;
}
