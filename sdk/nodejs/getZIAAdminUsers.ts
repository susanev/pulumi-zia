// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

/**
 * Use the **zia_admin_users** data source to get information about an admin user account created in the Zscaler Internet Access cloud or via the API. This data source can then be associated with a ZIA administrator role.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const johnDoe = zia.getZIAAdminUsers({
 *     loginName: "john.doe@example.com",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const johnDoe = zia.getZIAAdminUsers({
 *     username: "John Doe",
 * });
 * ```
 */
export function getZIAAdminUsers(args?: GetZIAAdminUsersArgs, opts?: pulumi.InvokeOptions): Promise<GetZIAAdminUsersResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIAAdminUsers:getZIAAdminUsers", {
        "id": args.id,
        "loginName": args.loginName,
        "username": args.username,
    }, opts);
}

/**
 * A collection of arguments for invoking getZIAAdminUsers.
 */
export interface GetZIAAdminUsersArgs {
    /**
     * The ID of the admin user to be exported.
     */
    id?: number;
    /**
     * The email address of the admin user to be exported.
     */
    loginName?: string;
    /**
     * The username of the admin user to be exported.
     */
    username?: string;
}

/**
 * A collection of values returned by getZIAAdminUsers.
 */
export interface GetZIAAdminUsersResult {
    /**
     * (Set of Object) The admin's scope. Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
     */
    readonly adminScopes: outputs.GetZIAAdminUsersAdminScope[];
    /**
     * (String) Additional information about the admin or auditor.
     */
    readonly comments: string;
    /**
     * (Boolean) Indicates whether or not the admin account is disabled.
     */
    readonly disabled: boolean;
    /**
     * (String) Admin or auditor's email address.
     */
    readonly email: string;
    /**
     * (List of Object)
     */
    readonly execMobileAppTokens: outputs.GetZIAAdminUsersExecMobileAppToken[];
    /**
     * (Number) Identifier that uniquely identifies an entity
     */
    readonly id: number;
    /**
     * (Boolean) Indicates whether the user is an auditor. This attribute is subject to change.
     */
    readonly isAuditor: boolean;
    /**
     * (Boolean) Indicates whether or not Executive Insights App access is enabled for the admin.
     */
    readonly isExecMobileAppEnabled: boolean;
    /**
     * (Boolean) Indicates whether or not the admin can be edited or deleted.
     */
    readonly isNonEditable: boolean;
    /**
     * (Boolean) Indicates whether or not an admin's password has expired.
     */
    readonly isPasswordExpired: boolean;
    /**
     * (Boolean) The default is true when SAML Authentication is disabled. When SAML Authentication is enabled, this can be set to false in order to force the admin to login via SSO only.
     */
    readonly isPasswordLoginAllowed: boolean;
    /**
     * (Boolean) Communication setting for Product Update.
     */
    readonly isProductUpdateCommEnabled: boolean;
    /**
     * (Boolean) Communication for Security Report is enabled.
     */
    readonly isSecurityReportCommEnabled: boolean;
    /**
     * (Boolean) Communication setting for Service Update.
     */
    readonly isServiceUpdateCommEnabled: boolean;
    readonly loginName: string;
    readonly pwdLastModifiedTime: number;
    /**
     * (Set of Object) Role of the admin. This is not required for an auditor.
     */
    readonly roles: outputs.GetZIAAdminUsersRole[];
    readonly username: string;
}
/**
 * Use the **zia_admin_users** data source to get information about an admin user account created in the Zscaler Internet Access cloud or via the API. This data source can then be associated with a ZIA administrator role.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const johnDoe = zia.getZIAAdminUsers({
 *     loginName: "john.doe@example.com",
 * });
 * ```
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const johnDoe = zia.getZIAAdminUsers({
 *     username: "John Doe",
 * });
 * ```
 */
export function getZIAAdminUsersOutput(args?: GetZIAAdminUsersOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetZIAAdminUsersResult> {
    return pulumi.output(args).apply((a: any) => getZIAAdminUsers(a, opts))
}

/**
 * A collection of arguments for invoking getZIAAdminUsers.
 */
export interface GetZIAAdminUsersOutputArgs {
    /**
     * The ID of the admin user to be exported.
     */
    id?: pulumi.Input<number>;
    /**
     * The email address of the admin user to be exported.
     */
    loginName?: pulumi.Input<string>;
    /**
     * The username of the admin user to be exported.
     */
    username?: pulumi.Input<string>;
}