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

    public sealed class ZIADLPWebRulesTimeWindowsArgs : global::Pulumi.ResourceArgs
    {
        [Input("ids", required: true)]
        private InputList<int>? _ids;

        /// <summary>
        /// Identifier that uniquely identifies an entity
        /// </summary>
        public InputList<int> Ids
        {
            get => _ids ?? (_ids = new InputList<int>());
            set => _ids = value;
        }

        public ZIADLPWebRulesTimeWindowsArgs()
        {
        }
        public static new ZIADLPWebRulesTimeWindowsArgs Empty => new ZIADLPWebRulesTimeWindowsArgs();
    }
}