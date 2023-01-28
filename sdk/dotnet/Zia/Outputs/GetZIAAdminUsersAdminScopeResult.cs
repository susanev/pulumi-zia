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
    public sealed class GetZIAAdminUsersAdminScopeResult
    {
        /// <summary>
        /// (String) Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAAdminUsersAdminScopeScopeEntityResult> ScopeEntities;
        /// <summary>
        /// (Number) Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAAdminUsersAdminScopeScopeGroupMemberEntityResult> ScopeGroupMemberEntities;
        /// <summary>
        /// (String) The admin scope type. The attribute name is subject to change.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetZIAAdminUsersAdminScopeResult(
            ImmutableArray<Outputs.GetZIAAdminUsersAdminScopeScopeEntityResult> scopeEntities,

            ImmutableArray<Outputs.GetZIAAdminUsersAdminScopeScopeGroupMemberEntityResult> scopeGroupMemberEntities,

            string type)
        {
            ScopeEntities = scopeEntities;
            ScopeGroupMemberEntities = scopeGroupMemberEntities;
            Type = type;
        }
    }
}
