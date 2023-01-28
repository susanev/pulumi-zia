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
    /// <summary>
    /// The provider type for the zia package. By default, resources use package-wide configuration
    /// settings, however an explicit `Provider` instance may be created and passed during resource
    /// construction to achieve fine-grained programmatic control over provider settings. See the
    /// [documentation](https://www.pulumi.com/docs/reference/programming-model/#providers) for more information.
    /// </summary>
    [ZiaResourceType("pulumi:providers:zia")]
    public partial class Provider : global::Pulumi.ProviderResource
    {
        [Output("apiKey")]
        public Output<string?> ApiKey { get; private set; } = null!;

        [Output("password")]
        public Output<string?> Password { get; private set; } = null!;

        [Output("username")]
        public Output<string?> Username { get; private set; } = null!;

        [Output("ziaCloud")]
        public Output<string?> ZiaCloud { get; private set; } = null!;


        /// <summary>
        /// Create a Provider resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Provider(string name, ProviderArgs? args = null, CustomResourceOptions? options = null)
            : base("zia", name, args ?? new ProviderArgs(), MakeResourceOptions(options, ""))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/zscaler",
                AdditionalSecretOutputs =
                {
                    "apiKey",
                    "password",
                },
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class ProviderArgs : global::Pulumi.ResourceArgs
    {
        [Input("apiKey")]
        private Input<string>? _apiKey;
        public Input<string>? ApiKey
        {
            get => _apiKey;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _apiKey = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        [Input("password")]
        private Input<string>? _password;
        public Input<string>? Password
        {
            get => _password;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _password = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        [Input("username")]
        public Input<string>? Username { get; set; }

        [Input("ziaCloud")]
        public Input<string>? ZiaCloud { get; set; }

        public ProviderArgs()
        {
            ApiKey = Utilities.GetEnv("ZIA_API_KEY");
            Password = Utilities.GetEnv("ZIA_PASSWORD");
            Username = Utilities.GetEnv("ZIA_USERNAME");
            ZiaCloud = Utilities.GetEnv("ZIA_CLOUD");
        }
        public static new ProviderArgs Empty => new ProviderArgs();
    }
}
