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

    public sealed class GetZIALocationGroupsDynamicLocationGroupCriteriaArgs : global::Pulumi.InvokeArgs
    {
        [Input("cities")]
        private List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCityArgs>? _cities;

        /// <summary>
        /// (Block List)
        /// </summary>
        public List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCityArgs> Cities
        {
            get => _cities ?? (_cities = new List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaCityArgs>());
            set => _cities = value;
        }

        [Input("countries")]
        private List<string>? _countries;

        /// <summary>
        /// (List of String) One or more countries from a predefined set
        /// </summary>
        public List<string> Countries
        {
            get => _countries ?? (_countries = new List<string>());
            set => _countries = value;
        }

        /// <summary>
        /// (Boolean) Enable Bandwidth Control. When set to true, Bandwidth Control is enabled for the location.
        /// </summary>
        [Input("enableBandwidthControl", required: true)]
        public bool EnableBandwidthControl { get; set; }

        /// <summary>
        /// (Boolean) Enable Caution. When set to true, a caution notifcation is enabled for the location.
        /// </summary>
        [Input("enableCaution", required: true)]
        public bool EnableCaution { get; set; }

        /// <summary>
        /// (Boolean) Enable `XFF` Forwarding. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header.
        /// </summary>
        [Input("enableXffForwarding", required: true)]
        public bool EnableXffForwarding { get; set; }

        /// <summary>
        /// (Boolean) Enable AUP. When set to true, AUP is enabled for the location.
        /// </summary>
        [Input("enforceAup", required: true)]
        public bool EnforceAup { get; set; }

        /// <summary>
        /// (Boolean) Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled.
        /// </summary>
        [Input("enforceAuthentication", required: true)]
        public bool EnforceAuthentication { get; set; }

        /// <summary>
        /// (Boolean) Enable Firewall. When set to true, Firewall is enabled for the location.
        /// </summary>
        [Input("enforceFirewallControl", required: true)]
        public bool EnforceFirewallControl { get; set; }

        [Input("managedBies", required: true)]
        private List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs>? _managedBies;

        /// <summary>
        /// (Block List)
        /// </summary>
        public List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs> ManagedBies
        {
            get => _managedBies ?? (_managedBies = new List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaManagedByArgs>());
            set => _managedBies = value;
        }

        [Input("names")]
        private List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaNameArgs>? _names;

        /// <summary>
        /// Location group name
        /// </summary>
        public List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaNameArgs> Names
        {
            get => _names ?? (_names = new List<Inputs.GetZIALocationGroupsDynamicLocationGroupCriteriaNameArgs>());
            set => _names = value;
        }

        [Input("profiles")]
        private List<string>? _profiles;

        /// <summary>
        /// (List of String) One or more location profiles from a predefined set
        /// </summary>
        public List<string> Profiles
        {
            get => _profiles ?? (_profiles = new List<string>());
            set => _profiles = value;
        }

        public GetZIALocationGroupsDynamicLocationGroupCriteriaArgs()
        {
        }
        public static new GetZIALocationGroupsDynamicLocationGroupCriteriaArgs Empty => new GetZIALocationGroupsDynamicLocationGroupCriteriaArgs();
    }
}