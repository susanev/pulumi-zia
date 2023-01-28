// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.Inputs
{

    public sealed class ZIAAdminUsersAdminScopeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
        /// </summary>
        [Input("scopeEntities")]
        public Input<Inputs.ZIAAdminUsersAdminScopeScopeEntitiesArgs>? ScopeEntities { get; set; }

        /// <summary>
        /// Only applicable for the LOCATION_GROUP admin scope type, in which case this attribute gives the list of ID/name pairs of locations within the location group.
        /// </summary>
        [Input("scopeGroupMemberEntities")]
        public Input<Inputs.ZIAAdminUsersAdminScopeScopeGroupMemberEntitiesArgs>? ScopeGroupMemberEntities { get; set; }

        /// <summary>
        /// The admin scope type. The attribute name is subject to change.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public ZIAAdminUsersAdminScopeArgs()
        {
        }
        public static new ZIAAdminUsersAdminScopeArgs Empty => new ZIAAdminUsersAdminScopeArgs();
    }
}
