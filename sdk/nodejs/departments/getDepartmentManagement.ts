// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export function getDepartmentManagement(args?: GetDepartmentManagementArgs, opts?: pulumi.InvokeOptions): Promise<GetDepartmentManagementResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:Departments/getDepartmentManagement:getDepartmentManagement", {
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getDepartmentManagement.
 */
export interface GetDepartmentManagementArgs {
    name?: string;
}

/**
 * A collection of values returned by getDepartmentManagement.
 */
export interface GetDepartmentManagementResult {
    readonly comments: string;
    readonly deleted: boolean;
    readonly id: number;
    readonly idpId: number;
    readonly name?: string;
}
export function getDepartmentManagementOutput(args?: GetDepartmentManagementOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDepartmentManagementResult> {
    return pulumi.output(args).apply((a: any) => getDepartmentManagement(a, opts))
}

/**
 * A collection of arguments for invoking getDepartmentManagement.
 */
export interface GetDepartmentManagementOutputArgs {
    name?: pulumi.Input<string>;
}
