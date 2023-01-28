// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.Outputs
{

    [OutputType]
    public sealed class GetZIALocationGroupsDynamicLocationGroupCriteriaNameResult
    {
        /// <summary>
        /// (String) String value to be matched or partially matched
        /// </summary>
        public readonly string? MatchString;
        /// <summary>
        /// (String) Operator that performs match action
        /// </summary>
        public readonly string? MatchType;

        [OutputConstructor]
        private GetZIALocationGroupsDynamicLocationGroupCriteriaNameResult(
            string? matchString,

            string? matchType)
        {
            MatchString = matchString;
            MatchType = matchType;
        }
    }
}
