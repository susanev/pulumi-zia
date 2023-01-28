// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

/**
 * Use the **zia_auth_settings_urls** data source to get a list of URLs that were exempted from cookie authentiation and SSL Inspection in the Zscaler Internet Access cloud or via the API. To learn more see [URL Format Guidelines](https://help.zscaler.com/zia/url-format-guidelines)
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@pulumi/zia";
 *
 * const foo = zia.getZIAAuthSettingsURLs({});
 * ```
 */
export function getZIAAuthSettingsURLs(opts?: pulumi.InvokeOptions): Promise<GetZIAAuthSettingsURLsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("zia:index/getZIAAuthSettingsURLs:getZIAAuthSettingsURLs", {
    }, opts);
}

/**
 * A collection of values returned by getZIAAuthSettingsURLs.
 */
export interface GetZIAAuthSettingsURLsResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly urls: string[];
}
