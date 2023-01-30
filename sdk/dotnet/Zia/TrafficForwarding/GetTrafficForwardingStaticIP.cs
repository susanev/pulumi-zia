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
    public static class GetTrafficForwardingStaticIP
    {
        /// <summary>
        /// Use the **zia_traffic_forwarding_static_ip** data source to get information about all provisioned static IP addresses. This resource can then be utilized when creating a GRE Tunnel or VPN Credential resource of Type `IP`
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
        ///     var example = Zia.TrafficForwarding.GetTrafficForwardingStaticIP.Invoke(new()
        ///     {
        ///         IpAddress = "1.1.1.1",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetTrafficForwardingStaticIPResult> InvokeAsync(GetTrafficForwardingStaticIPArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTrafficForwardingStaticIPResult>("zia:TrafficForwarding/getTrafficForwardingStaticIP:getTrafficForwardingStaticIP", args ?? new GetTrafficForwardingStaticIPArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_traffic_forwarding_static_ip** data source to get information about all provisioned static IP addresses. This resource can then be utilized when creating a GRE Tunnel or VPN Credential resource of Type `IP`
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
        ///     var example = Zia.TrafficForwarding.GetTrafficForwardingStaticIP.Invoke(new()
        ///     {
        ///         IpAddress = "1.1.1.1",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetTrafficForwardingStaticIPResult> Invoke(GetTrafficForwardingStaticIPInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTrafficForwardingStaticIPResult>("zia:TrafficForwarding/getTrafficForwardingStaticIP:getTrafficForwardingStaticIP", args ?? new GetTrafficForwardingStaticIPInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTrafficForwardingStaticIPArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Additional information about this static IP address
        /// </summary>
        [Input("comment")]
        public string? Comment { get; set; }

        /// <summary>
        /// The unique identifier for the static IP address
        /// </summary>
        [Input("id")]
        public int? Id { get; set; }

        /// <summary>
        /// The static IP address
        /// </summary>
        [Input("ipAddress")]
        public string? IpAddress { get; set; }

        public GetTrafficForwardingStaticIPArgs()
        {
        }
        public static new GetTrafficForwardingStaticIPArgs Empty => new GetTrafficForwardingStaticIPArgs();
    }

    public sealed class GetTrafficForwardingStaticIPInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Additional information about this static IP address
        /// </summary>
        [Input("comment")]
        public Input<string>? Comment { get; set; }

        /// <summary>
        /// The unique identifier for the static IP address
        /// </summary>
        [Input("id")]
        public Input<int>? Id { get; set; }

        /// <summary>
        /// The static IP address
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        public GetTrafficForwardingStaticIPInvokeArgs()
        {
        }
        public static new GetTrafficForwardingStaticIPInvokeArgs Empty => new GetTrafficForwardingStaticIPInvokeArgs();
    }


    [OutputType]
    public sealed class GetTrafficForwardingStaticIPResult
    {
        /// <summary>
        /// (String) Additional information about this static IP address
        /// </summary>
        public readonly string? Comment;
        /// <summary>
        /// (Boolean) If not set, geographic coordinates and city are automatically determined from the IP address. Otherwise, the latitude and longitude coordinates must be provided.
        /// </summary>
        public readonly bool GeoOverride;
        /// <summary>
        /// (String) Identifier that uniquely identifies an entity
        /// </summary>
        public readonly int Id;
        /// <summary>
        /// (String) The static IP address
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// (Number) When the static IP address was last modified
        /// </summary>
        public readonly int LastModificationTime;
        /// <summary>
        /// (Set of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTrafficForwardingStaticIPLastModifiedByResult> LastModifiedBies;
        /// <summary>
        /// (Number) Required only if the geoOverride attribute is set. Latitude with 7 digit precision after decimal point, ranges between `-90` and `90` degrees.
        /// </summary>
        public readonly int Latitude;
        /// <summary>
        /// (Number) Required only if the geoOverride attribute is set. Longitude with 7 digit precision after decimal point, ranges between `-180` and `180` degrees.
        /// </summary>
        public readonly int Longitude;
        /// <summary>
        /// (Set of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTrafficForwardingStaticIPManagedByResult> ManagedBies;
        /// <summary>
        /// (Boolean) Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is ignored if there is no ZIA Private Service Edge associated to the organization.
        /// </summary>
        public readonly bool RoutableIp;

        [OutputConstructor]
        private GetTrafficForwardingStaticIPResult(
            string? comment,

            bool geoOverride,

            int id,

            string ipAddress,

            int lastModificationTime,

            ImmutableArray<Outputs.GetTrafficForwardingStaticIPLastModifiedByResult> lastModifiedBies,

            int latitude,

            int longitude,

            ImmutableArray<Outputs.GetTrafficForwardingStaticIPManagedByResult> managedBies,

            bool routableIp)
        {
            Comment = comment;
            GeoOverride = geoOverride;
            Id = id;
            IpAddress = ipAddress;
            LastModificationTime = lastModificationTime;
            LastModifiedBies = lastModifiedBies;
            Latitude = latitude;
            Longitude = longitude;
            ManagedBies = managedBies;
            RoutableIp = routableIp;
        }
    }
}