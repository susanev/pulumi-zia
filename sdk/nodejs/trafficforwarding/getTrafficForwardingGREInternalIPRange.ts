// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

export function getTrafficForwardingGREInternalIPRange(args?: GetTrafficForwardingGREInternalIPRangeArgs, opts?: pulumi.InvokeOptions): Promise<GetTrafficForwardingGREInternalIPRangeResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:TrafficForwarding/getTrafficForwardingGREInternalIPRange:getTrafficForwardingGREInternalIPRange", {
        "requiredCount": args.requiredCount,
    }, opts);
}

/**
 * A collection of arguments for invoking getTrafficForwardingGREInternalIPRange.
 */
export interface GetTrafficForwardingGREInternalIPRangeArgs {
    requiredCount?: number;
}

/**
 * A collection of values returned by getTrafficForwardingGREInternalIPRange.
 */
export interface GetTrafficForwardingGREInternalIPRangeResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly lists: outputs.TrafficForwarding.GetTrafficForwardingGREInternalIPRangeList[];
    readonly requiredCount?: number;
}
export function getTrafficForwardingGREInternalIPRangeOutput(args?: GetTrafficForwardingGREInternalIPRangeOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetTrafficForwardingGREInternalIPRangeResult> {
    return pulumi.output(args).apply((a: any) => getTrafficForwardingGREInternalIPRange(a, opts))
}

/**
 * A collection of arguments for invoking getTrafficForwardingGREInternalIPRange.
 */
export interface GetTrafficForwardingGREInternalIPRangeOutputArgs {
    requiredCount?: pulumi.Input<number>;
}
