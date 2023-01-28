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
    public static class GetZIALocationGroups
    {
        /// <summary>
        /// Use the **zia_location_groups** data source to get information about a location group option available in the Zscaler Internet Access.
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Corporate User Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Guest Wifi Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "IoT Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Server Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Server Traffic Group",
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetZIALocationGroupsResult> InvokeAsync(GetZIALocationGroupsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIALocationGroupsResult>("zia:index/getZIALocationGroups:getZIALocationGroups", args ?? new GetZIALocationGroupsArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_location_groups** data source to get information about a location group option available in the Zscaler Internet Access.
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Corporate User Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Guest Wifi Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "IoT Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Server Traffic Group",
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
        ///     var example = Zia.GetZIALocationGroups.Invoke(new()
        ///     {
        ///         Name = "Server Traffic Group",
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetZIALocationGroupsResult> Invoke(GetZIALocationGroupsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIALocationGroupsResult>("zia:index/getZIALocationGroups:getZIALocationGroups", args ?? new GetZIALocationGroupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIALocationGroupsArgs : global::Pulumi.InvokeArgs
    {
        [Input("dynamicLocationGroupCriterias")]
        private List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaArgs>? _dynamicLocationGroupCriterias;

        /// <summary>
        /// (Block Set) Dynamic location group information.
        /// </summary>
        public List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaArgs> DynamicLocationGroupCriterias
        {
            get => _dynamicLocationGroupCriterias ?? (_dynamicLocationGroupCriterias = new List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaArgs>());
            set => _dynamicLocationGroupCriterias = value;
        }

        /// <summary>
        /// Location group name
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetZIALocationGroupsArgs()
        {
        }
        public static new GetZIALocationGroupsArgs Empty => new GetZIALocationGroupsArgs();
    }

    public sealed class GetZIALocationGroupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("dynamicLocationGroupCriterias")]
        private InputList<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaInputArgs>? _dynamicLocationGroupCriterias;

        /// <summary>
        /// (Block Set) Dynamic location group information.
        /// </summary>
        public InputList<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaInputArgs> DynamicLocationGroupCriterias
        {
            get => _dynamicLocationGroupCriterias ?? (_dynamicLocationGroupCriterias = new InputList<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaInputArgs>());
            set => _dynamicLocationGroupCriterias = value;
        }

        /// <summary>
        /// Location group name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public GetZIALocationGroupsInvokeArgs()
        {
        }
        public static new GetZIALocationGroupsInvokeArgs Empty => new GetZIALocationGroupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIALocationGroupsResult
    {
        /// <summary>
        /// (List of Object)
        /// </summary>
        public readonly string Comments;
        /// <summary>
        /// (Boolean) Indicates the location group was deleted
        /// </summary>
        public readonly bool Deleted;
        /// <summary>
        /// (Block Set) Dynamic location group information.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIALocationGroupsDynamicLocationGroupCriteriaResult> DynamicLocationGroupCriterias;
        /// <summary>
        /// (String) The location group's type (i.e., Static or Dynamic)
        /// </summary>
        public readonly string GroupType;
        /// <summary>
        /// (Number) Identifier that uniquely identifies an entity
        /// </summary>
        public readonly int Id;
        /// <summary>
        /// (List of Object) Automatically populated with the current time, after a successful POST or PUT request.
        /// </summary>
        public readonly int LastModTime;
        /// <summary>
        /// (List of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIALocationGroupsLastModUserResult> LastModUsers;
        /// <summary>
        /// (List of Object) The Name-ID pairs of the locations that are assigned to the static location group. This is ignored if the groupType is Dynamic.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIALocationGroupsLocationResult> Locations;
        /// <summary>
        /// (String) The configured name of the entity
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Boolean)
        /// </summary>
        public readonly bool Predefined;

        [OutputConstructor]
        private GetZIALocationGroupsResult(
            string comments,

            bool deleted,

            ImmutableArray<Outputs.GetZIALocationGroupsDynamicLocationGroupCriteriaResult> dynamicLocationGroupCriterias,

            string groupType,

            int id,

            int lastModTime,

            ImmutableArray<Outputs.GetZIALocationGroupsLastModUserResult> lastModUsers,

            ImmutableArray<Outputs.GetZIALocationGroupsLocationResult> locations,

            string? name,

            bool predefined)
        {
            Comments = comments;
            Deleted = deleted;
            DynamicLocationGroupCriterias = dynamicLocationGroupCriterias;
            GroupType = groupType;
            Id = id;
            LastModTime = lastModTime;
            LastModUsers = lastModUsers;
            Locations = locations;
            Name = name;
            Predefined = predefined;
        }
    }
}