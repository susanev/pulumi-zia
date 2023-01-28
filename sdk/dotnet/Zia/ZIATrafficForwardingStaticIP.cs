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
    /// The **zia_traffic_forwarding_static_ip** resource allows the creation and management of static ip addresses in the Zscaler Internet Access cloud. The resource, can then be associated with other resources such as:
    /// 
    /// * VPN Credentials of type `IP`
    /// * Location Management
    /// * GRE Tunnel
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Zia = zscaler.PulumiPackage.Zia;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     // ZIA Traffic Forwarding - Static IP
    ///     var example = new Zia.ZIATrafficForwardingStaticIP("example", new()
    ///     {
    ///         Comment = "Example",
    ///         GeoOverride = true,
    ///         IpAddress = "1.1.1.1",
    ///         Latitude = -36.848461,
    ///         Longitude = 174.763336,
    ///         RoutableIp = true,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Static IP resources can be imported by using `&lt;STATIC IP ID&gt;` or `&lt;IP ADDRESS&gt;`as the import ID.
    /// 
    /// ```sh
    ///  $ pulumi import zia:index/zIATrafficForwardingStaticIP:ZIATrafficForwardingStaticIP example &lt;static_ip_id&gt;
    /// ```
    /// 
    ///  or
    /// 
    /// ```sh
    ///  $ pulumi import zia:index/zIATrafficForwardingStaticIP:ZIATrafficForwardingStaticIP example &lt;ip_address&gt;
    /// ```
    /// </summary>
    [ZiaResourceType("zia:index/zIATrafficForwardingStaticIP:ZIATrafficForwardingStaticIP")]
    public partial class ZIATrafficForwardingStaticIP : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Additional information about this static IP address
        /// </summary>
        [Output("comment")]
        public Output<string?> Comment { get; private set; } = null!;

        /// <summary>
        /// If not set, geographic coordinates and city are automatically determined from the IP address. Otherwise, the latitude and longitude coordinates must be provided.
        /// </summary>
        [Output("geoOverride")]
        public Output<bool> GeoOverride { get; private set; } = null!;

        /// <summary>
        /// The static IP address
        /// </summary>
        [Output("ipAddress")]
        public Output<string> IpAddress { get; private set; } = null!;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        [Output("lastModifiedBies")]
        public Output<ImmutableArray<Outputs.ZIATrafficForwardingStaticIPLastModifiedBy>> LastModifiedBies { get; private set; } = null!;

        /// <summary>
        /// Required only if the geoOverride attribute is set. Latitude with 7 digit precision after decimal point, ranges between -90 and 90 degrees.
        /// </summary>
        [Output("latitude")]
        public Output<double> Latitude { get; private set; } = null!;

        /// <summary>
        /// Required only if the geoOverride attribute is set. Longitude with 7 digit precision after decimal point, ranges between -180 and 180 degrees.
        /// </summary>
        [Output("longitude")]
        public Output<double> Longitude { get; private set; } = null!;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        [Output("managedBies")]
        public Output<ImmutableArray<Outputs.ZIATrafficForwardingStaticIPManagedBy>> ManagedBies { get; private set; } = null!;

        /// <summary>
        /// Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is ignored if there is no ZIA Private Service Edge associated to the organization.
        /// </summary>
        [Output("routableIp")]
        public Output<bool> RoutableIp { get; private set; } = null!;

        /// <summary>
        /// The ID of the Static IP.
        /// </summary>
        [Output("staticIpId")]
        public Output<int> StaticIpId { get; private set; } = null!;


        /// <summary>
        /// Create a ZIATrafficForwardingStaticIP resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ZIATrafficForwardingStaticIP(string name, ZIATrafficForwardingStaticIPArgs args, CustomResourceOptions? options = null)
            : base("zia:index/zIATrafficForwardingStaticIP:ZIATrafficForwardingStaticIP", name, args ?? new ZIATrafficForwardingStaticIPArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ZIATrafficForwardingStaticIP(string name, Input<string> id, ZIATrafficForwardingStaticIPState? state = null, CustomResourceOptions? options = null)
            : base("zia:index/zIATrafficForwardingStaticIP:ZIATrafficForwardingStaticIP", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/zscaler",
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ZIATrafficForwardingStaticIP resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ZIATrafficForwardingStaticIP Get(string name, Input<string> id, ZIATrafficForwardingStaticIPState? state = null, CustomResourceOptions? options = null)
        {
            return new ZIATrafficForwardingStaticIP(name, id, state, options);
        }
    }

    public sealed class ZIATrafficForwardingStaticIPArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Additional information about this static IP address
        /// </summary>
        [Input("comment")]
        public Input<string>? Comment { get; set; }

        /// <summary>
        /// If not set, geographic coordinates and city are automatically determined from the IP address. Otherwise, the latitude and longitude coordinates must be provided.
        /// </summary>
        [Input("geoOverride")]
        public Input<bool>? GeoOverride { get; set; }

        /// <summary>
        /// The static IP address
        /// </summary>
        [Input("ipAddress", required: true)]
        public Input<string> IpAddress { get; set; } = null!;

        [Input("lastModifiedBies")]
        private InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByArgs>? _lastModifiedBies;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        public InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByArgs> LastModifiedBies
        {
            get => _lastModifiedBies ?? (_lastModifiedBies = new InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByArgs>());
            set => _lastModifiedBies = value;
        }

        /// <summary>
        /// Required only if the geoOverride attribute is set. Latitude with 7 digit precision after decimal point, ranges between -90 and 90 degrees.
        /// </summary>
        [Input("latitude")]
        public Input<double>? Latitude { get; set; }

        /// <summary>
        /// Required only if the geoOverride attribute is set. Longitude with 7 digit precision after decimal point, ranges between -180 and 180 degrees.
        /// </summary>
        [Input("longitude")]
        public Input<double>? Longitude { get; set; }

        [Input("managedBies")]
        private InputList<Inputs.ZIATrafficForwardingStaticIPManagedByArgs>? _managedBies;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        public InputList<Inputs.ZIATrafficForwardingStaticIPManagedByArgs> ManagedBies
        {
            get => _managedBies ?? (_managedBies = new InputList<Inputs.ZIATrafficForwardingStaticIPManagedByArgs>());
            set => _managedBies = value;
        }

        /// <summary>
        /// Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is ignored if there is no ZIA Private Service Edge associated to the organization.
        /// </summary>
        [Input("routableIp")]
        public Input<bool>? RoutableIp { get; set; }

        public ZIATrafficForwardingStaticIPArgs()
        {
        }
        public static new ZIATrafficForwardingStaticIPArgs Empty => new ZIATrafficForwardingStaticIPArgs();
    }

    public sealed class ZIATrafficForwardingStaticIPState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Additional information about this static IP address
        /// </summary>
        [Input("comment")]
        public Input<string>? Comment { get; set; }

        /// <summary>
        /// If not set, geographic coordinates and city are automatically determined from the IP address. Otherwise, the latitude and longitude coordinates must be provided.
        /// </summary>
        [Input("geoOverride")]
        public Input<bool>? GeoOverride { get; set; }

        /// <summary>
        /// The static IP address
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        [Input("lastModifiedBies")]
        private InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByGetArgs>? _lastModifiedBies;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        public InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByGetArgs> LastModifiedBies
        {
            get => _lastModifiedBies ?? (_lastModifiedBies = new InputList<Inputs.ZIATrafficForwardingStaticIPLastModifiedByGetArgs>());
            set => _lastModifiedBies = value;
        }

        /// <summary>
        /// Required only if the geoOverride attribute is set. Latitude with 7 digit precision after decimal point, ranges between -90 and 90 degrees.
        /// </summary>
        [Input("latitude")]
        public Input<double>? Latitude { get; set; }

        /// <summary>
        /// Required only if the geoOverride attribute is set. Longitude with 7 digit precision after decimal point, ranges between -180 and 180 degrees.
        /// </summary>
        [Input("longitude")]
        public Input<double>? Longitude { get; set; }

        [Input("managedBies")]
        private InputList<Inputs.ZIATrafficForwardingStaticIPManagedByGetArgs>? _managedBies;

        /// <summary>
        /// This is an immutable reference to an entity. which mainly consists of id and name
        /// </summary>
        public InputList<Inputs.ZIATrafficForwardingStaticIPManagedByGetArgs> ManagedBies
        {
            get => _managedBies ?? (_managedBies = new InputList<Inputs.ZIATrafficForwardingStaticIPManagedByGetArgs>());
            set => _managedBies = value;
        }

        /// <summary>
        /// Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is ignored if there is no ZIA Private Service Edge associated to the organization.
        /// </summary>
        [Input("routableIp")]
        public Input<bool>? RoutableIp { get; set; }

        /// <summary>
        /// The ID of the Static IP.
        /// </summary>
        [Input("staticIpId")]
        public Input<int>? StaticIpId { get; set; }

        public ZIATrafficForwardingStaticIPState()
        {
        }
        public static new ZIATrafficForwardingStaticIPState Empty => new ZIATrafficForwardingStaticIPState();
    }
}