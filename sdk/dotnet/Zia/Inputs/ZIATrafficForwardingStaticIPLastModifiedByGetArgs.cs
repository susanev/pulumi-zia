// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.Inputs
{

    public sealed class ZIATrafficForwardingStaticIPLastModifiedByGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("extensions")]
        private InputMap<string>? _extensions;
        public InputMap<string> Extensions
        {
            get => _extensions ?? (_extensions = new InputMap<string>());
            set => _extensions = value;
        }

        [Input("id")]
        public Input<int>? Id { get; set; }

        [Input("name")]
        public Input<string>? Name { get; set; }

        public ZIATrafficForwardingStaticIPLastModifiedByGetArgs()
        {
        }
        public static new ZIATrafficForwardingStaticIPLastModifiedByGetArgs Empty => new ZIATrafficForwardingStaticIPLastModifiedByGetArgs();
    }
}
