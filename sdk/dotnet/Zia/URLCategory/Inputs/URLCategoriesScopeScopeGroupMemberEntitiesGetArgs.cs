// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.URLCategory.Inputs
{

    public sealed class URLCategoriesScopeScopeGroupMemberEntitiesGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("ids", required: true)]
        private InputList<int>? _ids;
        public InputList<int> Ids
        {
            get => _ids ?? (_ids = new InputList<int>());
            set => _ids = value;
        }

        public URLCategoriesScopeScopeGroupMemberEntitiesGetArgs()
        {
        }
        public static new URLCategoriesScopeScopeGroupMemberEntitiesGetArgs Empty => new URLCategoriesScopeScopeGroupMemberEntitiesGetArgs();
    }
}
