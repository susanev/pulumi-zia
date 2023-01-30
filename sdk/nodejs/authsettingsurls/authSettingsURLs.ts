// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * The **zia_auth_settings_urls** resource alows you to add or remove a URL from the cookie authentication exempt list in the Zscaler Internet Access cloud or via the API. To learn more see [URL Format Guidelines](https://help.zscaler.com/zia/url-format-guidelines)
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@zscaler/pulumi-zia";
 *
 * // ZIA User Auth Settings Data Source
 * const example = new zia.authsettingsurls.AuthSettingsURLs("example", {urls: [
 *     ".okta.com",
 *     ".oktacdn.com",
 *     ".mtls.oktapreview.com",
 *     ".mtls.okta.com",
 *     "d3l44rcogcb7iv.cloudfront.net",
 *     "pac.zdxcloud.net",
 *     ".windowsazure.com",
 *     ".fedoraproject.org",
 *     "login.windows.net",
 *     "d32a6ru7mhaq0c.cloudfront.net",
 *     ".kerberos.oktapreview.com",
 *     ".oktapreview.com",
 *     "login.zdxcloud.net",
 *     "login.microsoftonline.com",
 *     "smres.zdxcloud.net",
 *     ".kerberos.okta.com",
 * ]});
 * ```
 */
export class AuthSettingsURLs extends pulumi.CustomResource {
    /**
     * Get an existing AuthSettingsURLs resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AuthSettingsURLsState, opts?: pulumi.CustomResourceOptions): AuthSettingsURLs {
        return new AuthSettingsURLs(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'zia:AuthSettingsUrls/authSettingsURLs:AuthSettingsURLs';

    /**
     * Returns true if the given object is an instance of AuthSettingsURLs.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AuthSettingsURLs {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AuthSettingsURLs.__pulumiType;
    }

    /**
     * The email address of the admin user to be exported.
     */
    public readonly urls!: pulumi.Output<string[]>;

    /**
     * Create a AuthSettingsURLs resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: AuthSettingsURLsArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AuthSettingsURLsArgs | AuthSettingsURLsState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AuthSettingsURLsState | undefined;
            resourceInputs["urls"] = state ? state.urls : undefined;
        } else {
            const args = argsOrState as AuthSettingsURLsArgs | undefined;
            resourceInputs["urls"] = args ? args.urls : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AuthSettingsURLs.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AuthSettingsURLs resources.
 */
export interface AuthSettingsURLsState {
    /**
     * The email address of the admin user to be exported.
     */
    urls?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a AuthSettingsURLs resource.
 */
export interface AuthSettingsURLsArgs {
    /**
     * The email address of the admin user to be exported.
     */
    urls?: pulumi.Input<pulumi.Input<string>[]>;
}