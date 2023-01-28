// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

/**
 * Use the **zia_devices** data source to get information about a device in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: URL Filtering Rules
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const device = zia.getZIADevices({
 *     name: "administrator",
 * });
 * ```
 */
export function getZIADevices(args?: GetZIADevicesArgs, opts?: pulumi.InvokeOptions): Promise<GetZIADevicesResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIADevices:getZIADevices", {
        "deviceGroupType": args.deviceGroupType,
        "deviceModel": args.deviceModel,
        "name": args.name,
        "osType": args.osType,
        "osVersion": args.osVersion,
        "ownerName": args.ownerName,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIADevices.
 */
export interface GetZIADevicesArgs {
    /**
     * (String) The device group type. i.e ``ZCC_OS``, ``NON_ZCC``, ``CBI``
     */
    deviceGroupType?: string;
    /**
     * (String) The device model.
     */
    deviceModel?: string;
    /**
     * The name of the devices to be exported.
     */
    name?: string;
    /**
     * (String) The operating system (OS). ``ANY``, ``OTHER_OS``, ``IOS``, ``ANDROID_OS``, ``WINDOWS_OS``, ``MAC_OS``, ``LINUX``
     */
    osType?: string;
    /**
     * (String) The operating system version.
     */
    osVersion?: string;
    /**
     * (String) The device owner's user name.
     */
    ownerName?: string;
}

/**
 * A collection of values returned by getZIADevices.
 */
export interface GetZIADevicesResult {
    /**
     * (String) The device's description.
     */
    readonly description: string;
    /**
     * (String) The device group type. i.e ``ZCC_OS``, ``NON_ZCC``, ``CBI``
     */
    readonly deviceGroupType: string;
    /**
     * (String) The device model.
     */
    readonly deviceModel: string;
    /**
     * (String) The unique identifer for the device group.
     */
    readonly id: number;
    /**
     * (String) The device name.
     */
    readonly name: string;
    /**
     * (String) The operating system (OS). ``ANY``, ``OTHER_OS``, ``IOS``, ``ANDROID_OS``, ``WINDOWS_OS``, ``MAC_OS``, ``LINUX``
     */
    readonly osType: string;
    /**
     * (String) The operating system version.
     */
    readonly osVersion: string;
    /**
     * (String) The device owner's user name.
     */
    readonly ownerName: string;
    /**
     * (int) The unique identifier of the device owner (i.e., user).
     */
    readonly ownerUserId: number;
}
/**
 * Use the **zia_devices** data source to get information about a device in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: URL Filtering Rules
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const device = zia.getZIADevices({
 *     name: "administrator",
 * });
 * ```
 */
export function getZIADevicesOutput(args?: GetZIADevicesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIADevicesResult> {
    return pulumi.output(args).apply((a: any) => getZIADevices(a, opts))
}

/**
 * A collection of arguments for invoking getZIADevices.
 */
export interface GetZIADevicesOutputArgs {
    /**
     * (String) The device group type. i.e ``ZCC_OS``, ``NON_ZCC``, ``CBI``
     */
    deviceGroupType?: pulumi.Input<string>;
    /**
     * (String) The device model.
     */
    deviceModel?: pulumi.Input<string>;
    /**
     * The name of the devices to be exported.
     */
    name?: pulumi.Input<string>;
    /**
     * (String) The operating system (OS). ``ANY``, ``OTHER_OS``, ``IOS``, ``ANDROID_OS``, ``WINDOWS_OS``, ``MAC_OS``, ``LINUX``
     */
    osType?: pulumi.Input<string>;
    /**
     * (String) The operating system version.
     */
    osVersion?: pulumi.Input<string>;
    /**
     * (String) The device owner's user name.
     */
    ownerName?: pulumi.Input<string>;
}
