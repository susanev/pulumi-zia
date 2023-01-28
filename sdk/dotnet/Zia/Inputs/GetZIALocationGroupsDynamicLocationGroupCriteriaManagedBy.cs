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

    public sealed class GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs : global::Pulumi.InvokeArgs
    {
        [Input("extensions", required: true)]
        private Dictionary<string, string>? _extensions;

        /// <summary>
        /// (Map of String)
        /// </summary>
        public Dictionary<string, string> Extensions
        {
            get => _extensions ?? (_extensions = new Dictionary<string, string>());
            set => _extensions = value;
        }

        /// <summary>
        /// Unique identifier for the location group
        /// </summary>
        [Input("id", required: true)]
        public int Id { get; set; }

        /// <summary>
        /// Location group name
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        public GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs()
        {
        }
        public static new GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs Empty => new GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs();
    }
}
