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
    public sealed class GetZIAURLCategoriesScopeResult
    {
        /// <summary>
        /// (List of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAURLCategoriesScopeScopeEntityResult> ScopeEntities;
        /// <summary>
        /// (List of Object) Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group. The attribute name is subject to change.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAURLCategoriesScopeScopeGroupMemberEntityResult> ScopeGroupMemberEntities;
        /// <summary>
        /// (String) The admin scope type. The attribute name is subject to change. `ORGANIZATION`, `DEPARTMENT`, `LOCATION`, `LOCATION_GROUP`
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetZIAURLCategoriesScopeResult(
            ImmutableArray<Outputs.GetZIAURLCategoriesScopeScopeEntityResult> scopeEntities,

            ImmutableArray<Outputs.GetZIAURLCategoriesScopeScopeGroupMemberEntityResult> scopeGroupMemberEntities,

            string type)
        {
            ScopeEntities = scopeEntities;
            ScopeGroupMemberEntities = scopeGroupMemberEntities;
            Type = type;
        }
    }
}
