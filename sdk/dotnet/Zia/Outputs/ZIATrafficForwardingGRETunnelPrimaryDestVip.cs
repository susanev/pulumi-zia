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
    public sealed class ZIATrafficForwardingGRETunnelPrimaryDestVip
    {
        public readonly string? Datacenter;
        /// <summary>
        /// Unique identifer of the GRE virtual IP address (VIP)
        /// </summary>
        public readonly int? Id;
        public readonly bool? PrivateServiceEdge;
        /// <summary>
        /// GRE cluster virtual IP address (VIP)
        /// </summary>
        public readonly string? VirtualIp;

        [OutputConstructor]
        private ZIATrafficForwardingGRETunnelPrimaryDestVip(
            string? datacenter,

            int? id,

            bool? privateServiceEdge,

            string? virtualIp)
        {
            Datacenter = datacenter;
            Id = id;
            PrivateServiceEdge = privateServiceEdge;
            VirtualIp = virtualIp;
        }
    }
}
