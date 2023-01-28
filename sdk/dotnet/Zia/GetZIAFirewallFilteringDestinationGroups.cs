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
    public static class GetZIAFirewallFilteringDestinationGroups
    {
        /// <summary>
        /// Use the **zia_firewall_filtering_destination_groups** data source to get information about IP destination groups option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
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
        ///     var example = Zia.GetZIAFirewallFilteringDestinationGroups.Invoke(new()
        ///     {
        ///         Name = "example",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetZIAFirewallFilteringDestinationGroupsResult> InvokeAsync(GetZIAFirewallFilteringDestinationGroupsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIAFirewallFilteringDestinationGroupsResult>("zia:index/getZIAFirewallFilteringDestinationGroups:getZIAFirewallFilteringDestinationGroups", args ?? new GetZIAFirewallFilteringDestinationGroupsArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_firewall_filtering_destination_groups** data source to get information about IP destination groups option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
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
        ///     var example = Zia.GetZIAFirewallFilteringDestinationGroups.Invoke(new()
        ///     {
        ///         Name = "example",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetZIAFirewallFilteringDestinationGroupsResult> Invoke(GetZIAFirewallFilteringDestinationGroupsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIAFirewallFilteringDestinationGroupsResult>("zia:index/getZIAFirewallFilteringDestinationGroups:getZIAFirewallFilteringDestinationGroups", args ?? new GetZIAFirewallFilteringDestinationGroupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIAFirewallFilteringDestinationGroupsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the destination group resource.
        /// </summary>
        [Input("id")]
        public int? Id { get; set; }

        /// <summary>
        /// The name of the destination group to be exported.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetZIAFirewallFilteringDestinationGroupsArgs()
        {
        }
        public static new GetZIAFirewallFilteringDestinationGroupsArgs Empty => new GetZIAFirewallFilteringDestinationGroupsArgs();
    }

    public sealed class GetZIAFirewallFilteringDestinationGroupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the destination group resource.
        /// </summary>
        [Input("id")]
        public Input<int>? Id { get; set; }

        /// <summary>
        /// The name of the destination group to be exported.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public GetZIAFirewallFilteringDestinationGroupsInvokeArgs()
        {
        }
        public static new GetZIAFirewallFilteringDestinationGroupsInvokeArgs Empty => new GetZIAFirewallFilteringDestinationGroupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIAFirewallFilteringDestinationGroupsResult
    {
        /// <summary>
        /// (List of String) Destination IP addresses within the group
        /// </summary>
        public readonly ImmutableArray<string> Addresses;
        /// <summary>
        /// (List of String) Destination IP address counties. You can identify destinations based on the location of a server.
        /// </summary>
        public readonly ImmutableArray<string> Countries;
        /// <summary>
        /// (String) Additional information about the destination IP group
        /// </summary>
        public readonly string Description;
        public readonly int Id;
        /// <summary>
        /// (List of String) Destination IP address URL categories. You can identify destinations based on the URL category of the domain.
        /// </summary>
        public readonly ImmutableArray<string> IpCategories;
        public readonly string Name;
        /// <summary>
        /// (String) Destination IP group type (i.e., the group can contain destination IP addresses or FQDNs)
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetZIAFirewallFilteringDestinationGroupsResult(
            ImmutableArray<string> addresses,

            ImmutableArray<string> countries,

            string description,

            int id,

            ImmutableArray<string> ipCategories,

            string name,

            string type)
        {
            Addresses = addresses;
            Countries = countries;
            Description = description;
            Id = id;
            IpCategories = ipCategories;
            Name = name;
            Type = type;
        }
    }
}
