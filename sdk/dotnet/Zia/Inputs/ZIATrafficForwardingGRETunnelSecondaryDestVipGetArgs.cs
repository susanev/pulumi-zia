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

    public sealed class ZIATrafficForwardingGRETunnelSecondaryDestVipGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("datacenter")]
        public Input<string>? Datacenter { get; set; }

        /// <summary>
        /// Unique identifer of the GRE virtual IP address (VIP)
        /// </summary>
        [Input("id")]
        public Input<int>? Id { get; set; }

        [Input("privateServiceEdge")]
        public Input<bool>? PrivateServiceEdge { get; set; }

        /// <summary>
        /// GRE cluster virtual IP address (VIP)
        /// </summary>
        [Input("virtualIp")]
        public Input<string>? VirtualIp { get; set; }

        public ZIATrafficForwardingGRETunnelSecondaryDestVipGetArgs()
        {
        }
        public static new ZIATrafficForwardingGRETunnelSecondaryDestVipGetArgs Empty => new ZIATrafficForwardingGRETunnelSecondaryDestVipGetArgs();
    }
}
