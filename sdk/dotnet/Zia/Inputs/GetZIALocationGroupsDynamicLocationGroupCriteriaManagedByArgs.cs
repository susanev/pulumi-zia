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

    public sealed class GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByInputArgs : global::Pulumi.ResourceArgs
    {
        [Input("extensions", required: true)]
        private InputMap<string>? _extensions;

        /// <summary>
        /// (Map of String)
        /// </summary>
        public InputMap<string> Extensions
        {
            get => _extensions ?? (_extensions = new InputMap<string>());
            set => _extensions = value;
        }

        /// <summary>
        /// Unique identifier for the location group
        /// </summary>
        [Input("id", required: true)]
        public Input<int> Id { get; set; } = null!;

        /// <summary>
        /// Location group name
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByInputArgs()
        {
        }
        public static new GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByInputArgs Empty => new GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByInputArgs();
    }
}
