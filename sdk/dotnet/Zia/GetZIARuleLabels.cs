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
    public static class GetZIARuleLabels
    {
        /// <summary>
        /// Use the **zia_rule_labels** data source to get information about a rule label resource in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: Firewall Rules and URL filtering rules
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
        ///     var example = Zia.GetZIARuleLabels.Invoke(new()
        ///     {
        ///         Name = "Example",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetZIARuleLabelsResult> InvokeAsync(GetZIARuleLabelsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIARuleLabelsResult>("zia:index/getZIARuleLabels:getZIARuleLabels", args ?? new GetZIARuleLabelsArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_rule_labels** data source to get information about a rule label resource in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: Firewall Rules and URL filtering rules
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
        ///     var example = Zia.GetZIARuleLabels.Invoke(new()
        ///     {
        ///         Name = "Example",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetZIARuleLabelsResult> Invoke(GetZIARuleLabelsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIARuleLabelsResult>("zia:index/getZIARuleLabels:getZIARuleLabels", args ?? new GetZIARuleLabelsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIARuleLabelsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifer for the device group.
        /// </summary>
        [Input("id")]
        public int? Id { get; set; }

        /// <summary>
        /// The name of the rule label to be exported.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetZIARuleLabelsArgs()
        {
        }
        public static new GetZIARuleLabelsArgs Empty => new GetZIARuleLabelsArgs();
    }

    public sealed class GetZIARuleLabelsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifer for the device group.
        /// </summary>
        [Input("id")]
        public Input<int>? Id { get; set; }

        /// <summary>
        /// The name of the rule label to be exported.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public GetZIARuleLabelsInvokeArgs()
        {
        }
        public static new GetZIARuleLabelsInvokeArgs Empty => new GetZIARuleLabelsInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIARuleLabelsResult
    {
        /// <summary>
        /// (String) The admin that created the rule label. This is a read-only field. Ignored by PUT requests.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIARuleLabelsCreatedByResult> CreatedBies;
        /// <summary>
        /// (String) The rule label description.
        /// </summary>
        public readonly string Description;
        public readonly int Id;
        /// <summary>
        /// (String) The admin that modified the rule label last. This is a read-only field. Ignored by PUT requests.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIARuleLabelsLastModifiedByResult> LastModifiedBies;
        /// <summary>
        /// (String) Timestamp when the rule lable was last modified. This is a read-only field. Ignored by PUT and DELETE requests.
        /// </summary>
        public readonly int LastModifiedTime;
        public readonly string Name;
        /// <summary>
        /// (int) The number of rules that reference the label.
        /// </summary>
        public readonly int ReferencedRuleCount;

        [OutputConstructor]
        private GetZIARuleLabelsResult(
            ImmutableArray<Outputs.GetZIARuleLabelsCreatedByResult> createdBies,

            string description,

            int id,

            ImmutableArray<Outputs.GetZIARuleLabelsLastModifiedByResult> lastModifiedBies,

            int lastModifiedTime,

            string name,

            int referencedRuleCount)
        {
            CreatedBies = createdBies;
            Description = description;
            Id = id;
            LastModifiedBies = lastModifiedBies;
            LastModifiedTime = lastModifiedTime;
            Name = name;
            ReferencedRuleCount = referencedRuleCount;
        }
    }
}
