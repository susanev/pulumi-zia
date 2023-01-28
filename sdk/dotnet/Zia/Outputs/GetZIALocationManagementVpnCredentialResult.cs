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
    public sealed class GetZIALocationManagementVpnCredentialResult
    {
        /// <summary>
        /// (String) Additional information about this VPN credential.
        /// Additional information about this VPN credential.
        /// </summary>
        public readonly string Comments;
        /// <summary>
        /// (String) Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
        /// </summary>
        public readonly string Fqdn;
        /// <summary>
        /// The ID of the location to be exported.
        /// </summary>
        public readonly int Id;
        /// <summary>
        /// (List of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIALocationManagementVpnCredentialLocationResult> Locations;
        /// <summary>
        /// (List of Object)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIALocationManagementVpnCredentialManagedByResult> ManagedBies;
        /// <summary>
        /// (String) Pre-shared key. This is a required field for `UFQDN` and IP auth type.
        /// </summary>
        public readonly string PreSharedKey;
        /// <summary>
        /// (String) VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetZIALocationManagementVpnCredentialResult(
            string comments,

            string fqdn,

            int id,

            ImmutableArray<Outputs.GetZIALocationManagementVpnCredentialLocationResult> locations,

            ImmutableArray<Outputs.GetZIALocationManagementVpnCredentialManagedByResult> managedBies,

            string preSharedKey,

            string type)
        {
            Comments = comments;
            Fqdn = fqdn;
            Id = id;
            Locations = locations;
            ManagedBies = managedBies;
            PreSharedKey = preSharedKey;
            Type = type;
        }
    }
}