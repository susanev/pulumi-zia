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
    public static class GetZIATrafficForwardingVPNCredentials
    {
        /// <summary>
        /// Use the **zia_traffic_forwarding_vpn_credentials** data source to get information about VPN credentials that can be associated to locations. VPN is one way to route traffic from customer locations to the cloud. Site-to-Site IPSec VPN credentials can be identified by the cloud through one of the following methods:
        /// 
        /// * Common Name (CN) of IPSec Certificate
        /// * VPN User FQDN - requires VPN_SITE_TO_SITE subscription
        /// * VPN IP Address - requires VPN_SITE_TO_SITE subscription
        /// * Extended Authentication (XAUTH) or hosted mobile UserID - requires VPN_MOBILE subscription
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
        ///     var example = Zia.GetZIATrafficForwardingVPNCredentials.Invoke(new()
        ///     {
        ///         Fqdn = "sjc-1-37@acme.com",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIATrafficForwardingVPNCredentials.Invoke(new()
        ///     {
        ///         IpAddress = "1.1.1.1",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetZIATrafficForwardingVPNCredentialsResult> InvokeAsync(GetZIATrafficForwardingVPNCredentialsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIATrafficForwardingVPNCredentialsResult>("zia:index/getZIATrafficForwardingVPNCredentials:getZIATrafficForwardingVPNCredentials", args ?? new GetZIATrafficForwardingVPNCredentialsArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_traffic_forwarding_vpn_credentials** data source to get information about VPN credentials that can be associated to locations. VPN is one way to route traffic from customer locations to the cloud. Site-to-Site IPSec VPN credentials can be identified by the cloud through one of the following methods:
        /// 
        /// * Common Name (CN) of IPSec Certificate
        /// * VPN User FQDN - requires VPN_SITE_TO_SITE subscription
        /// * VPN IP Address - requires VPN_SITE_TO_SITE subscription
        /// * Extended Authentication (XAUTH) or hosted mobile UserID - requires VPN_MOBILE subscription
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
        ///     var example = Zia.GetZIATrafficForwardingVPNCredentials.Invoke(new()
        ///     {
        ///         Fqdn = "sjc-1-37@acme.com",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIATrafficForwardingVPNCredentials.Invoke(new()
        ///     {
        ///         IpAddress = "1.1.1.1",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetZIATrafficForwardingVPNCredentialsResult> Invoke(GetZIATrafficForwardingVPNCredentialsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIATrafficForwardingVPNCredentialsResult>("zia:index/getZIATrafficForwardingVPNCredentials:getZIATrafficForwardingVPNCredentials", args ?? new GetZIATrafficForwardingVPNCredentialsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIATrafficForwardingVPNCredentialsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        /// </summary>
        [Input("fqdn")]
        public string? Fqdn { get; set; }

        /// <summary>
        /// Unique identifer of the GRE virtual IP address (VIP)
        /// </summary>
        [Input("id")]
        public int? Id { get; set; }

        /// <summary>
        /// Filter based on an IP address range.
        /// </summary>
        [Input("ipAddress")]
        public string? IpAddress { get; set; }

        /// <summary>
        /// (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        /// </summary>
        [Input("type")]
        public string? Type { get; set; }

        public GetZIATrafficForwardingVPNCredentialsArgs()
        {
        }
        public static new GetZIATrafficForwardingVPNCredentialsArgs Empty => new GetZIATrafficForwardingVPNCredentialsArgs();
    }

    public sealed class GetZIATrafficForwardingVPNCredentialsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        /// </summary>
        [Input("fqdn")]
        public Input<string>? Fqdn { get; set; }

        /// <summary>
        /// Unique identifer of the GRE virtual IP address (VIP)
        /// </summary>
        [Input("id")]
        public Input<int>? Id { get; set; }

        /// <summary>
        /// Filter based on an IP address range.
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        /// <summary>
        /// (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public GetZIATrafficForwardingVPNCredentialsInvokeArgs()
        {
        }
        public static new GetZIATrafficForwardingVPNCredentialsInvokeArgs Empty => new GetZIATrafficForwardingVPNCredentialsInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIATrafficForwardingVPNCredentialsResult
    {
        /// <summary>
        /// (String) Additional information about this VPN credential.
        /// </summary>
        public readonly string Comments;
        /// <summary>
        /// (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        /// </summary>
        public readonly string? Fqdn;
        /// <summary>
        /// (Number) Identifier that uniquely identifies an entity
        /// </summary>
        public readonly int Id;
        public readonly string? IpAddress;
        /// <summary>
        /// (Set of Object) Location that is associated to this VPN credential. Non-existence means not associated to any location.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIATrafficForwardingVPNCredentialsLocationResult> Locations;
        /// <summary>
        /// (Set of Object) SD-WAN Partner that manages the location. If a partner does not manage the locaton, this is set to Self.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIATrafficForwardingVPNCredentialsManagedByResult> ManagedBies;
        /// <summary>
        /// (String) Pre-shared key. This is a required field for `UFQDN` and `IP` auth type.
        /// </summary>
        public readonly string PreSharedKey;
        /// <summary>
        /// (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetZIATrafficForwardingVPNCredentialsResult(
            string comments,

            string? fqdn,

            int id,

            string? ipAddress,

            ImmutableArray<Outputs.GetZIATrafficForwardingVPNCredentialsLocationResult> locations,

            ImmutableArray<Outputs.GetZIATrafficForwardingVPNCredentialsManagedByResult> managedBies,

            string preSharedKey,

            string type)
        {
            Comments = comments;
            Fqdn = fqdn;
            Id = id;
            IpAddress = ipAddress;
            Locations = locations;
            ManagedBies = managedBies;
            PreSharedKey = preSharedKey;
            Type = type;
        }
    }
}