// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Use the **zia_device_groups** data source to get information about a device group in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: URL Filtering Rules
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const ios = zia.DeviceGroups.getDeviceGroups({
 *     name: "IOS",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const android = zia.DeviceGroups.getDeviceGroups({
 *     name: "Android",
 * });
 * ```
 */
export function getDeviceGroups(args?: GetDeviceGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetDeviceGroupsResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:DeviceGroups/getDeviceGroups:getDeviceGroups", {
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeviceGroups.
 */
export interface GetDeviceGroupsArgs {
    /**
     * The name of the device group to be exported.
     */
    name?: string;
}

/**
 * A collection of values returned by getDeviceGroups.
 */
export interface GetDeviceGroupsResult {
    /**
     * (String) The device group's description.
     */
    readonly description: string;
    /**
     * (int) The number of devices within the group.
     */
    readonly deviceCount: number;
    /**
     * (String) The names of devices that belong to the device group. The device names are comma-separated.
     */
    readonly deviceNames: string;
    /**
     * (String) The device group type. i.e ``ZCC_OS``, ``NON_ZCC``, ``CBI``
     */
    readonly groupType: string;
    /**
     * (String) The unique identifer for the device group.
     */
    readonly id: number;
    /**
     * (String) The device group name.
     */
    readonly name?: string;
    /**
     * (String) The operating system (OS).
     */
    readonly osType: string;
    /**
     * (Boolean) Indicates whether this is a predefined device group. If this value is set to true, the group is predefined.
     */
    readonly predefined: boolean;
}
/**
 * Use the **zia_device_groups** data source to get information about a device group in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: URL Filtering Rules
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const ios = zia.DeviceGroups.getDeviceGroups({
 *     name: "IOS",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const android = zia.DeviceGroups.getDeviceGroups({
 *     name: "Android",
 * });
 * ```
 */
export function getDeviceGroupsOutput(args?: GetDeviceGroupsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDeviceGroupsResult> {
    return pulumi.output(args).apply((a: any) => getDeviceGroups(a, opts))
}

/**
 * A collection of arguments for invoking getDeviceGroups.
 */
export interface GetDeviceGroupsOutputArgs {
    /**
     * The name of the device group to be exported.
     */
    name?: pulumi.Input<string>;
}