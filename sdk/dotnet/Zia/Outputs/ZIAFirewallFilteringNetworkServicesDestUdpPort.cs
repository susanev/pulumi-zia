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
    public sealed class ZIAFirewallFilteringNetworkServicesDestUdpPort
    {
        public readonly int? End;
        public readonly int? Start;

        [OutputConstructor]
        private ZIAFirewallFilteringNetworkServicesDestUdpPort(
            int? end,

            int? start)
        {
            End = end;
            Start = start;
        }
    }
}