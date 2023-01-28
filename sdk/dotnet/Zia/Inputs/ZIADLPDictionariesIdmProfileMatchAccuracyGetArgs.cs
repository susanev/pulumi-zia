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

    public sealed class ZIADLPDictionariesIdmProfileMatchAccuracyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The IDM template reference.
        /// </summary>
        [Input("adpIdmProfile")]
        public Input<Inputs.ZIADLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileGetArgs>? AdpIdmProfile { get; set; }

        /// <summary>
        /// The IDM template match accuracy.
        /// - `"LOW"`
        /// - `"MEDIUM"`
        /// - `"HEAVY"`
        /// </summary>
        [Input("matchAccuracy")]
        public Input<string>? MatchAccuracy { get; set; }

        public ZIADLPDictionariesIdmProfileMatchAccuracyGetArgs()
        {
        }
        public static new ZIADLPDictionariesIdmProfileMatchAccuracyGetArgs Empty => new ZIADLPDictionariesIdmProfileMatchAccuracyGetArgs();
    }
}
