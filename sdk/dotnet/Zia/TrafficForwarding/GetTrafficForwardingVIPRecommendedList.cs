// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.TrafficForwarding
{
    public static class GetTrafficForwardingVIPRecommendedList
    {
        /// <summary>
        /// Use the **zia_gre_vip_recommended_list** data source to get information about a list of recommended GRE tunnel virtual IP addresses (VIPs), based on source IP address or latitude/longitude coordinates.
        /// </summary>
        public static Task<GetTrafficForwardingVIPRecommendedListResult> InvokeAsync(GetTrafficForwardingVIPRecommendedListArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTrafficForwardingVIPRecommendedListResult>("zia:TrafficForwarding/getTrafficForwardingVIPRecommendedList:getTrafficForwardingVIPRecommendedList", args ?? new GetTrafficForwardingVIPRecommendedListArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_gre_vip_recommended_list** data source to get information about a list of recommended GRE tunnel virtual IP addresses (VIPs), based on source IP address or latitude/longitude coordinates.
        /// </summary>
        public static Output<GetTrafficForwardingVIPRecommendedListResult> Invoke(GetTrafficForwardingVIPRecommendedListInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTrafficForwardingVIPRecommendedListResult>("zia:TrafficForwarding/getTrafficForwardingVIPRecommendedList:getTrafficForwardingVIPRecommendedList", args ?? new GetTrafficForwardingVIPRecommendedListInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTrafficForwardingVIPRecommendedListArgs : global::Pulumi.InvokeArgs
    {
        [Input("geoOverride")]
        public bool? GeoOverride { get; set; }

        [Input("requiredCount")]
        public int? RequiredCount { get; set; }

        [Input("routableIp")]
        public bool? RoutableIp { get; set; }

        /// <summary>
        /// (String) The public source IP address.
        /// </summary>
        [Input("sourceIp")]
        public string? SourceIp { get; set; }

        public GetTrafficForwardingVIPRecommendedListArgs()
        {
        }
        public static new GetTrafficForwardingVIPRecommendedListArgs Empty => new GetTrafficForwardingVIPRecommendedListArgs();
    }

    public sealed class GetTrafficForwardingVIPRecommendedListInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("geoOverride")]
        public Input<bool>? GeoOverride { get; set; }

        [Input("requiredCount")]
        public Input<int>? RequiredCount { get; set; }

        [Input("routableIp")]
        public Input<bool>? RoutableIp { get; set; }

        /// <summary>
        /// (String) The public source IP address.
        /// </summary>
        [Input("sourceIp")]
        public Input<string>? SourceIp { get; set; }

        public GetTrafficForwardingVIPRecommendedListInvokeArgs()
        {
        }
        public static new GetTrafficForwardingVIPRecommendedListInvokeArgs Empty => new GetTrafficForwardingVIPRecommendedListInvokeArgs();
    }


    [OutputType]
    public sealed class GetTrafficForwardingVIPRecommendedListResult
    {
        public readonly bool? GeoOverride;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<Outputs.GetTrafficForwardingVIPRecommendedListListResult> Lists;
        public readonly int? RequiredCount;
        public readonly bool? RoutableIp;
        /// <summary>
        /// (String) The public source IP address.
        /// </summary>
        public readonly string? SourceIp;

        [OutputConstructor]
        private GetTrafficForwardingVIPRecommendedListResult(
            bool? geoOverride,

            string id,

            ImmutableArray<Outputs.GetTrafficForwardingVIPRecommendedListListResult> lists,

            int? requiredCount,

            bool? routableIp,

            string? sourceIp)
        {
            GeoOverride = geoOverride;
            Id = id;
            Lists = lists;
            RequiredCount = requiredCount;
            RoutableIp = routableIp;
            SourceIp = sourceIp;
        }
    }
}