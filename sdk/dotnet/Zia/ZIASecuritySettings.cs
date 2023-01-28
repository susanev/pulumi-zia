// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia
{
    [ZiaResourceType("zia:index/zIASecuritySettings:ZIASecuritySettings")]
    public partial class ZIASecuritySettings : global::Pulumi.CustomResource
    {
        /// <summary>
        /// URLs on the denylist for your organization. Allow up to 25000 URLs.
        /// </summary>
        [Output("blacklistUrls")]
        public Output<ImmutableArray<string>> BlacklistUrls { get; private set; } = null!;

        /// <summary>
        /// Allowlist URLs whose contents will not be scanned. Allows up to 255 URLs.
        /// </summary>
        [Output("whitelistUrls")]
        public Output<ImmutableArray<string>> WhitelistUrls { get; private set; } = null!;


        /// <summary>
        /// Create a ZIASecuritySettings resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ZIASecuritySettings(string name, ZIASecuritySettingsArgs? args = null, CustomResourceOptions? options = null)
            : base("zia:index/zIASecuritySettings:ZIASecuritySettings", name, args ?? new ZIASecuritySettingsArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ZIASecuritySettings(string name, Input<string> id, ZIASecuritySettingsState? state = null, CustomResourceOptions? options = null)
            : base("zia:index/zIASecuritySettings:ZIASecuritySettings", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/zscaler",
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ZIASecuritySettings resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ZIASecuritySettings Get(string name, Input<string> id, ZIASecuritySettingsState? state = null, CustomResourceOptions? options = null)
        {
            return new ZIASecuritySettings(name, id, state, options);
        }
    }

    public sealed class ZIASecuritySettingsArgs : global::Pulumi.ResourceArgs
    {
        [Input("blacklistUrls")]
        private InputList<string>? _blacklistUrls;

        /// <summary>
        /// URLs on the denylist for your organization. Allow up to 25000 URLs.
        /// </summary>
        public InputList<string> BlacklistUrls
        {
            get => _blacklistUrls ?? (_blacklistUrls = new InputList<string>());
            set => _blacklistUrls = value;
        }

        [Input("whitelistUrls")]
        private InputList<string>? _whitelistUrls;

        /// <summary>
        /// Allowlist URLs whose contents will not be scanned. Allows up to 255 URLs.
        /// </summary>
        public InputList<string> WhitelistUrls
        {
            get => _whitelistUrls ?? (_whitelistUrls = new InputList<string>());
            set => _whitelistUrls = value;
        }

        public ZIASecuritySettingsArgs()
        {
        }
        public static new ZIASecuritySettingsArgs Empty => new ZIASecuritySettingsArgs();
    }

    public sealed class ZIASecuritySettingsState : global::Pulumi.ResourceArgs
    {
        [Input("blacklistUrls")]
        private InputList<string>? _blacklistUrls;

        /// <summary>
        /// URLs on the denylist for your organization. Allow up to 25000 URLs.
        /// </summary>
        public InputList<string> BlacklistUrls
        {
            get => _blacklistUrls ?? (_blacklistUrls = new InputList<string>());
            set => _blacklistUrls = value;
        }

        [Input("whitelistUrls")]
        private InputList<string>? _whitelistUrls;

        /// <summary>
        /// Allowlist URLs whose contents will not be scanned. Allows up to 255 URLs.
        /// </summary>
        public InputList<string> WhitelistUrls
        {
            get => _whitelistUrls ?? (_whitelistUrls = new InputList<string>());
            set => _whitelistUrls = value;
        }

        public ZIASecuritySettingsState()
        {
        }
        public static new ZIASecuritySettingsState Empty => new ZIASecuritySettingsState();
    }
}