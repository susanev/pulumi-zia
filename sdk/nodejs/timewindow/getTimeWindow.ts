// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Use the **zia_firewall_filtering_time_window** data source to get information about a time window option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const workHours = zia.TimeWindow.getTimeWindow({
 *     name: "Work hours",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const weekends = zia.TimeWindow.getTimeWindow({
 *     name: "Weekends",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const offHours = zia.TimeWindow.getTimeWindow({
 *     name: "Off hours",
 * });
 * ```
 */
export function getTimeWindow(args?: GetTimeWindowArgs, opts?: pulumi.InvokeOptions): Promise<GetTimeWindowResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:TimeWindow/getTimeWindow:getTimeWindow", {
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getTimeWindow.
 */
export interface GetTimeWindowArgs {
    /**
     * The name of the time window to be exported.
     */
    name?: string;
}

/**
 * A collection of values returned by getTimeWindow.
 */
export interface GetTimeWindowResult {
    /**
     * (String). The supported values are:
     */
    readonly dayOfWeeks: string[];
    /**
     * (String)
     */
    readonly endTime: number;
    readonly id: number;
    readonly name?: string;
    /**
     * (String)
     */
    readonly startTime: number;
}
/**
 * Use the **zia_firewall_filtering_time_window** data source to get information about a time window option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const workHours = zia.TimeWindow.getTimeWindow({
 *     name: "Work hours",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const weekends = zia.TimeWindow.getTimeWindow({
 *     name: "Weekends",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const offHours = zia.TimeWindow.getTimeWindow({
 *     name: "Off hours",
 * });
 * ```
 */
export function getTimeWindowOutput(args?: GetTimeWindowOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetTimeWindowResult> {
    return pulumi.output(args).apply((a: any) => getTimeWindow(a, opts))
}

/**
 * A collection of arguments for invoking getTimeWindow.
 */
export interface GetTimeWindowOutputArgs {
    /**
     * The name of the time window to be exported.
     */
    name?: pulumi.Input<string>;
}