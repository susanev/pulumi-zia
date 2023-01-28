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
    public static class GetZIATrafficForwardingNodeVIPs
    {
        /// <summary>
        /// Use the **zia_traffic_forwarding_public_node_vips** data source to retrieve a paginated list of virtual IP addresses (VIPs) available in the Zscaler cloud.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var yvr1 = Zia.GetZIATrafficForwardingNodeVIPs.Invoke(new()
        ///     {
        ///         Datacenter = "YVR1",
        ///     });
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["ziaTrafficForwardingPublicNodeVipsYvr1"] = yvr1.Apply(getZIATrafficForwardingNodeVIPsResult =&gt; getZIATrafficForwardingNodeVIPsResult),
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetZIATrafficForwardingNodeVIPsResult> InvokeAsync(GetZIATrafficForwardingNodeVIPsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIATrafficForwardingNodeVIPsResult>("zia:index/getZIATrafficForwardingNodeVIPs:getZIATrafficForwardingNodeVIPs", args ?? new GetZIATrafficForwardingNodeVIPsArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_traffic_forwarding_public_node_vips** data source to retrieve a paginated list of virtual IP addresses (VIPs) available in the Zscaler cloud.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var yvr1 = Zia.GetZIATrafficForwardingNodeVIPs.Invoke(new()
        ///     {
        ///         Datacenter = "YVR1",
        ///     });
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["ziaTrafficForwardingPublicNodeVipsYvr1"] = yvr1.Apply(getZIATrafficForwardingNodeVIPsResult =&gt; getZIATrafficForwardingNodeVIPsResult),
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetZIATrafficForwardingNodeVIPsResult> Invoke(GetZIATrafficForwardingNodeVIPsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIATrafficForwardingNodeVIPsResult>("zia:index/getZIATrafficForwardingNodeVIPs:getZIATrafficForwardingNodeVIPs", args ?? new GetZIATrafficForwardingNodeVIPsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIATrafficForwardingNodeVIPsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Data-center Name
        /// </summary>
        [Input("datacenter")]
        public string? Datacenter { get; set; }

        public GetZIATrafficForwardingNodeVIPsArgs()
        {
        }
        public static new GetZIATrafficForwardingNodeVIPsArgs Empty => new GetZIATrafficForwardingNodeVIPsArgs();
    }

    public sealed class GetZIATrafficForwardingNodeVIPsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Data-center Name
        /// </summary>
        [Input("datacenter")]
        public Input<string>? Datacenter { get; set; }

        public GetZIATrafficForwardingNodeVIPsInvokeArgs()
        {
        }
        public static new GetZIATrafficForwardingNodeVIPsInvokeArgs Empty => new GetZIATrafficForwardingNodeVIPsInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIATrafficForwardingNodeVIPsResult
    {
        public readonly string City;
        public readonly string CloudName;
        public readonly string? Datacenter;
        public readonly string GreDomainName;
        public readonly ImmutableArray<string> GreIps;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string Location;
        public readonly string PacDomainName;
        public readonly ImmutableArray<string> PacIps;
        public readonly string Region;
        public readonly string VpnDomainName;
        public readonly ImmutableArray<string> VpnIps;

        [OutputConstructor]
        private GetZIATrafficForwardingNodeVIPsResult(
            string city,

            string cloudName,

            string? datacenter,

            string greDomainName,

            ImmutableArray<string> greIps,

            string id,

            string location,

            string pacDomainName,

            ImmutableArray<string> pacIps,

            string region,

            string vpnDomainName,

            ImmutableArray<string> vpnIps)
        {
            City = city;
            CloudName = cloudName;
            Datacenter = datacenter;
            GreDomainName = greDomainName;
            GreIps = greIps;
            Id = id;
            Location = location;
            PacDomainName = pacDomainName;
            PacIps = pacIps;
            Region = region;
            VpnDomainName = vpnDomainName;
            VpnIps = vpnIps;
        }
    }
}