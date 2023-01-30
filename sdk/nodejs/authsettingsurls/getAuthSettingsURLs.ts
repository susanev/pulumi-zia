// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Use the **zia_auth_settings_urls** data source to get a list of URLs that were exempted from cookie authentiation and SSL Inspection in the Zscaler Internet Access cloud or via the API. To learn more see [URL Format Guidelines](https://help.zscaler.com/zia/url-format-guidelines)
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const foo = zia.AuthSettingsUrls.getAuthSettingsURLs({});
 * ```
 */
export function getAuthSettingsURLs(opts?: pulumi.InvokeOptions): Promise<GetAuthSettingsURLsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:AuthSettingsUrls/getAuthSettingsURLs:getAuthSettingsURLs", {
    }, opts);
}

/**
 * A collection of values returned by getAuthSettingsURLs.
 */
export interface GetAuthSettingsURLsResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly urls: string[];
}