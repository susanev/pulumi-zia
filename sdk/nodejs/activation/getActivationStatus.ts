// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const activation = zia.Activation.getActivationStatus({});
 * ```
 */
export function getActivationStatus(opts?: pulumi.InvokeOptions): Promise<GetActivationStatusResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:Activation/getActivationStatus:getActivationStatus", {
    }, opts);
}

/**
 * A collection of values returned by getActivationStatus.
 */
export interface GetActivationStatusResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly status: string;
}