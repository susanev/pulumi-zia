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
    /// <summary>
    /// The **zia_dlp_web_rules** resource allows the creation and management of ZIA DLP Web Rules in the Zscaler Internet Access cloud or via the API.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Zia = zscaler.PulumiPackage.Zia;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var test = new Zia.ZIADLPWebRules("test", new()
    ///     {
    ///         Action = "ALLOW",
    ///         CloudApplications = new[]
    ///         {
    ///             "ZENDESK",
    ///             "LUCKY_ORANGE",
    ///             "MICROSOFT_POWERAPPS",
    ///             "MICROSOFTLIVEMEETING",
    ///         },
    ///         Description = "Test",
    ///         FileTypes = new[] {},
    ///         MatchOnly = false,
    ///         MinSize = 20,
    ///         OcrEnabled = false,
    ///         Order = 1,
    ///         Protocols = new[]
    ///         {
    ///             "HTTPS_RULE",
    ///             "HTTP_RULE",
    ///         },
    ///         Rank = 7,
    ///         State = "ENABLED",
    ///         WithoutContentInspection = false,
    ///         ZscalerIncidentReciever = true,
    ///     });
    /// 
    /// });
    /// ```
    /// </summary>
    [ZiaResourceType("zia:index/zIADLPWebRules:ZIADLPWebRules")]
    public partial class ZIADLPWebRules : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The access privilege for this DLP policy rule based on the admin's state. The supported values are:
        /// </summary>
        [Output("accessControl")]
        public Output<string> AccessControl { get; private set; } = null!;

        /// <summary>
        /// The action taken when traffic matches the DLP policy rule criteria. The supported values are:
        /// </summary>
        [Output("action")]
        public Output<string> Action { get; private set; } = null!;

        /// <summary>
        /// The auditor to which the DLP policy rule must be applied.
        /// </summary>
        [Output("auditor")]
        public Output<Outputs.ZIADLPWebRulesAuditor> Auditor { get; private set; } = null!;

        /// <summary>
        /// The list of cloud applications to which the DLP policy rule must be applied. For the complete list of supported cloud applications refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        [Output("cloudApplications")]
        public Output<ImmutableArray<string>> CloudApplications { get; private set; } = null!;

        /// <summary>
        /// The name-ID pairs of the departments that are excluded from the DLP policy rule.
        /// </summary>
        [Output("departments")]
        public Output<Outputs.ZIADLPWebRulesDepartments> Departments { get; private set; } = null!;

        /// <summary>
        /// The description of the DLP policy rule.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The list of DLP engines to which the DLP policy rule must be applied.
        /// </summary>
        [Output("dlpEngines")]
        public Output<Outputs.ZIADLPWebRulesDlpEngines> DlpEngines { get; private set; } = null!;

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` departments.
        /// </summary>
        [Output("excludedDepartments")]
        public Output<Outputs.ZIADLPWebRulesExcludedDepartments> ExcludedDepartments { get; private set; } = null!;

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` groups.
        /// </summary>
        [Output("excludedGroups")]
        public Output<Outputs.ZIADLPWebRulesExcludedGroups> ExcludedGroups { get; private set; } = null!;

        /// <summary>
        /// The name-ID pairs of the users that are excluded from the DLP policy rule. Maximum of up to `256` users.
        /// </summary>
        [Output("excludedUsers")]
        public Output<Outputs.ZIADLPWebRulesExcludedUsers> ExcludedUsers { get; private set; } = null!;

        /// <summary>
        /// The email address of an external auditor to whom DLP email notifications are sent.
        /// </summary>
        [Output("externalAuditorEmail")]
        public Output<string> ExternalAuditorEmail { get; private set; } = null!;

        /// <summary>
        /// The list of file types to which the DLP policy rule must be applied. For the complete list of supported file types refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        [Output("fileTypes")]
        public Output<ImmutableArray<string>> FileTypes { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of groups to which the DLP policy rule must be applied. Maximum of up to `8` groups. When not used it implies `Any` to apply the rule to all groups.
        /// </summary>
        [Output("groups")]
        public Output<Outputs.ZIADLPWebRulesGroups> Groups { get; private set; } = null!;

        /// <summary>
        /// The DLP server, using ICAP, to which the transaction content is forwarded.
        /// </summary>
        [Output("icapServer")]
        public Output<Outputs.ZIADLPWebRulesIcapServer> IcapServer { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of rule labels associated to the DLP policy rule.
        /// </summary>
        [Output("labels")]
        public Output<Outputs.ZIADLPWebRulesLabels> Labels { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of locations groups to which the DLP policy rule must be applied. Maximum of up to `32` location groups. When not used it implies `Any` to apply the rule to all location groups.
        /// </summary>
        [Output("locationGroups")]
        public Output<Outputs.ZIADLPWebRulesLocationGroups> LocationGroups { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of locations to which the DLP policy rule must be applied. Maximum of up to `8` locations. When not used it implies `Any` to apply the rule to all locations.
        /// </summary>
        [Output("locations")]
        public Output<Outputs.ZIADLPWebRulesLocations> Locations { get; private set; } = null!;

        /// <summary>
        /// The match only criteria for DLP engines.
        /// </summary>
        [Output("matchOnly")]
        public Output<bool> MatchOnly { get; private set; } = null!;

        /// <summary>
        /// The minimum file size (in KB) used for evaluation of the DLP policy rule.
        /// </summary>
        [Output("minSize")]
        public Output<int> MinSize { get; private set; } = null!;

        /// <summary>
        /// The DLP policy rule name.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The template used for DLP notification emails.
        /// </summary>
        [Output("notificationTemplate")]
        public Output<Outputs.ZIADLPWebRulesNotificationTemplate> NotificationTemplate { get; private set; } = null!;

        /// <summary>
        /// Enables or disables image file scanning.
        /// </summary>
        [Output("ocrEnabled")]
        public Output<bool> OcrEnabled { get; private set; } = null!;

        /// <summary>
        /// The rule order of execution for the DLP policy rule with respect to other rules.
        /// </summary>
        [Output("order")]
        public Output<int> Order { get; private set; } = null!;

        /// <summary>
        /// The protocol criteria specified for the DLP policy rule.
        /// </summary>
        [Output("protocols")]
        public Output<ImmutableArray<string>> Protocols { get; private set; } = null!;

        /// <summary>
        /// Admin rank of the admin who creates this rule
        /// </summary>
        [Output("rank")]
        public Output<int?> Rank { get; private set; } = null!;

        [Output("ruleId")]
        public Output<int> RuleId { get; private set; } = null!;

        /// <summary>
        /// Enables or disables the DLP policy rule.. The supported values are:
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of time windows to which the DLP policy rule must be applied. Maximum of up to `2` time intervals. When not used it implies `always` to apply the rule to all time intervals.
        /// </summary>
        [Output("timeWindows")]
        public Output<Outputs.ZIADLPWebRulesTimeWindows> TimeWindows { get; private set; } = null!;

        /// <summary>
        /// The list of URL categories to which the DLP policy rule must be applied.
        /// </summary>
        [Output("urlCategories")]
        public Output<Outputs.ZIADLPWebRulesUrlCategories> UrlCategories { get; private set; } = null!;

        /// <summary>
        /// The Name-ID pairs of users to which the DLP policy rule must be applied. Maximum of up to `4` users. When not used it implies `Any` to apply the rule to all users.
        /// </summary>
        [Output("users")]
        public Output<Outputs.ZIADLPWebRulesUsers> Users { get; private set; } = null!;

        /// <summary>
        /// Indicates a DLP policy rule without content inspection, when the value is set to true.
        /// </summary>
        [Output("withoutContentInspection")]
        public Output<bool> WithoutContentInspection { get; private set; } = null!;

        /// <summary>
        /// Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule.
        /// </summary>
        [Output("zscalerIncidentReciever")]
        public Output<bool> ZscalerIncidentReciever { get; private set; } = null!;


        /// <summary>
        /// Create a ZIADLPWebRules resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ZIADLPWebRules(string name, ZIADLPWebRulesArgs args, CustomResourceOptions? options = null)
            : base("zia:index/zIADLPWebRules:ZIADLPWebRules", name, args ?? new ZIADLPWebRulesArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ZIADLPWebRules(string name, Input<string> id, ZIADLPWebRulesState? state = null, CustomResourceOptions? options = null)
            : base("zia:index/zIADLPWebRules:ZIADLPWebRules", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/zscaler",
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ZIADLPWebRules resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ZIADLPWebRules Get(string name, Input<string> id, ZIADLPWebRulesState? state = null, CustomResourceOptions? options = null)
        {
            return new ZIADLPWebRules(name, id, state, options);
        }
    }

    public sealed class ZIADLPWebRulesArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The access privilege for this DLP policy rule based on the admin's state. The supported values are:
        /// </summary>
        [Input("accessControl")]
        public Input<string>? AccessControl { get; set; }

        /// <summary>
        /// The action taken when traffic matches the DLP policy rule criteria. The supported values are:
        /// </summary>
        [Input("action")]
        public Input<string>? Action { get; set; }

        /// <summary>
        /// The auditor to which the DLP policy rule must be applied.
        /// </summary>
        [Input("auditor")]
        public Input<Inputs.ZIADLPWebRulesAuditorArgs>? Auditor { get; set; }

        [Input("cloudApplications")]
        private InputList<string>? _cloudApplications;

        /// <summary>
        /// The list of cloud applications to which the DLP policy rule must be applied. For the complete list of supported cloud applications refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        public InputList<string> CloudApplications
        {
            get => _cloudApplications ?? (_cloudApplications = new InputList<string>());
            set => _cloudApplications = value;
        }

        /// <summary>
        /// The name-ID pairs of the departments that are excluded from the DLP policy rule.
        /// </summary>
        [Input("departments")]
        public Input<Inputs.ZIADLPWebRulesDepartmentsArgs>? Departments { get; set; }

        /// <summary>
        /// The description of the DLP policy rule.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The list of DLP engines to which the DLP policy rule must be applied.
        /// </summary>
        [Input("dlpEngines")]
        public Input<Inputs.ZIADLPWebRulesDlpEnginesArgs>? DlpEngines { get; set; }

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` departments.
        /// </summary>
        [Input("excludedDepartments")]
        public Input<Inputs.ZIADLPWebRulesExcludedDepartmentsArgs>? ExcludedDepartments { get; set; }

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` groups.
        /// </summary>
        [Input("excludedGroups")]
        public Input<Inputs.ZIADLPWebRulesExcludedGroupsArgs>? ExcludedGroups { get; set; }

        /// <summary>
        /// The name-ID pairs of the users that are excluded from the DLP policy rule. Maximum of up to `256` users.
        /// </summary>
        [Input("excludedUsers")]
        public Input<Inputs.ZIADLPWebRulesExcludedUsersArgs>? ExcludedUsers { get; set; }

        /// <summary>
        /// The email address of an external auditor to whom DLP email notifications are sent.
        /// </summary>
        [Input("externalAuditorEmail")]
        public Input<string>? ExternalAuditorEmail { get; set; }

        [Input("fileTypes")]
        private InputList<string>? _fileTypes;

        /// <summary>
        /// The list of file types to which the DLP policy rule must be applied. For the complete list of supported file types refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        public InputList<string> FileTypes
        {
            get => _fileTypes ?? (_fileTypes = new InputList<string>());
            set => _fileTypes = value;
        }

        /// <summary>
        /// The Name-ID pairs of groups to which the DLP policy rule must be applied. Maximum of up to `8` groups. When not used it implies `Any` to apply the rule to all groups.
        /// </summary>
        [Input("groups")]
        public Input<Inputs.ZIADLPWebRulesGroupsArgs>? Groups { get; set; }

        /// <summary>
        /// The DLP server, using ICAP, to which the transaction content is forwarded.
        /// </summary>
        [Input("icapServer")]
        public Input<Inputs.ZIADLPWebRulesIcapServerArgs>? IcapServer { get; set; }

        /// <summary>
        /// The Name-ID pairs of rule labels associated to the DLP policy rule.
        /// </summary>
        [Input("labels")]
        public Input<Inputs.ZIADLPWebRulesLabelsArgs>? Labels { get; set; }

        /// <summary>
        /// The Name-ID pairs of locations groups to which the DLP policy rule must be applied. Maximum of up to `32` location groups. When not used it implies `Any` to apply the rule to all location groups.
        /// </summary>
        [Input("locationGroups")]
        public Input<Inputs.ZIADLPWebRulesLocationGroupsArgs>? LocationGroups { get; set; }

        /// <summary>
        /// The Name-ID pairs of locations to which the DLP policy rule must be applied. Maximum of up to `8` locations. When not used it implies `Any` to apply the rule to all locations.
        /// </summary>
        [Input("locations")]
        public Input<Inputs.ZIADLPWebRulesLocationsArgs>? Locations { get; set; }

        /// <summary>
        /// The match only criteria for DLP engines.
        /// </summary>
        [Input("matchOnly")]
        public Input<bool>? MatchOnly { get; set; }

        /// <summary>
        /// The minimum file size (in KB) used for evaluation of the DLP policy rule.
        /// </summary>
        [Input("minSize")]
        public Input<int>? MinSize { get; set; }

        /// <summary>
        /// The DLP policy rule name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The template used for DLP notification emails.
        /// </summary>
        [Input("notificationTemplate")]
        public Input<Inputs.ZIADLPWebRulesNotificationTemplateArgs>? NotificationTemplate { get; set; }

        /// <summary>
        /// Enables or disables image file scanning.
        /// </summary>
        [Input("ocrEnabled")]
        public Input<bool>? OcrEnabled { get; set; }

        /// <summary>
        /// The rule order of execution for the DLP policy rule with respect to other rules.
        /// </summary>
        [Input("order", required: true)]
        public Input<int> Order { get; set; } = null!;

        [Input("protocols")]
        private InputList<string>? _protocols;

        /// <summary>
        /// The protocol criteria specified for the DLP policy rule.
        /// </summary>
        public InputList<string> Protocols
        {
            get => _protocols ?? (_protocols = new InputList<string>());
            set => _protocols = value;
        }

        /// <summary>
        /// Admin rank of the admin who creates this rule
        /// </summary>
        [Input("rank")]
        public Input<int>? Rank { get; set; }

        /// <summary>
        /// Enables or disables the DLP policy rule.. The supported values are:
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The Name-ID pairs of time windows to which the DLP policy rule must be applied. Maximum of up to `2` time intervals. When not used it implies `always` to apply the rule to all time intervals.
        /// </summary>
        [Input("timeWindows")]
        public Input<Inputs.ZIADLPWebRulesTimeWindowsArgs>? TimeWindows { get; set; }

        /// <summary>
        /// The list of URL categories to which the DLP policy rule must be applied.
        /// </summary>
        [Input("urlCategories")]
        public Input<Inputs.ZIADLPWebRulesUrlCategoriesArgs>? UrlCategories { get; set; }

        /// <summary>
        /// The Name-ID pairs of users to which the DLP policy rule must be applied. Maximum of up to `4` users. When not used it implies `Any` to apply the rule to all users.
        /// </summary>
        [Input("users")]
        public Input<Inputs.ZIADLPWebRulesUsersArgs>? Users { get; set; }

        /// <summary>
        /// Indicates a DLP policy rule without content inspection, when the value is set to true.
        /// </summary>
        [Input("withoutContentInspection")]
        public Input<bool>? WithoutContentInspection { get; set; }

        /// <summary>
        /// Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule.
        /// </summary>
        [Input("zscalerIncidentReciever")]
        public Input<bool>? ZscalerIncidentReciever { get; set; }

        public ZIADLPWebRulesArgs()
        {
        }
        public static new ZIADLPWebRulesArgs Empty => new ZIADLPWebRulesArgs();
    }

    public sealed class ZIADLPWebRulesState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The access privilege for this DLP policy rule based on the admin's state. The supported values are:
        /// </summary>
        [Input("accessControl")]
        public Input<string>? AccessControl { get; set; }

        /// <summary>
        /// The action taken when traffic matches the DLP policy rule criteria. The supported values are:
        /// </summary>
        [Input("action")]
        public Input<string>? Action { get; set; }

        /// <summary>
        /// The auditor to which the DLP policy rule must be applied.
        /// </summary>
        [Input("auditor")]
        public Input<Inputs.ZIADLPWebRulesAuditorGetArgs>? Auditor { get; set; }

        [Input("cloudApplications")]
        private InputList<string>? _cloudApplications;

        /// <summary>
        /// The list of cloud applications to which the DLP policy rule must be applied. For the complete list of supported cloud applications refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        public InputList<string> CloudApplications
        {
            get => _cloudApplications ?? (_cloudApplications = new InputList<string>());
            set => _cloudApplications = value;
        }

        /// <summary>
        /// The name-ID pairs of the departments that are excluded from the DLP policy rule.
        /// </summary>
        [Input("departments")]
        public Input<Inputs.ZIADLPWebRulesDepartmentsGetArgs>? Departments { get; set; }

        /// <summary>
        /// The description of the DLP policy rule.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The list of DLP engines to which the DLP policy rule must be applied.
        /// </summary>
        [Input("dlpEngines")]
        public Input<Inputs.ZIADLPWebRulesDlpEnginesGetArgs>? DlpEngines { get; set; }

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` departments.
        /// </summary>
        [Input("excludedDepartments")]
        public Input<Inputs.ZIADLPWebRulesExcludedDepartmentsGetArgs>? ExcludedDepartments { get; set; }

        /// <summary>
        /// The name-ID pairs of the groups that are excluded from the DLP policy rule. Maximum of up to `256` groups.
        /// </summary>
        [Input("excludedGroups")]
        public Input<Inputs.ZIADLPWebRulesExcludedGroupsGetArgs>? ExcludedGroups { get; set; }

        /// <summary>
        /// The name-ID pairs of the users that are excluded from the DLP policy rule. Maximum of up to `256` users.
        /// </summary>
        [Input("excludedUsers")]
        public Input<Inputs.ZIADLPWebRulesExcludedUsersGetArgs>? ExcludedUsers { get; set; }

        /// <summary>
        /// The email address of an external auditor to whom DLP email notifications are sent.
        /// </summary>
        [Input("externalAuditorEmail")]
        public Input<string>? ExternalAuditorEmail { get; set; }

        [Input("fileTypes")]
        private InputList<string>? _fileTypes;

        /// <summary>
        /// The list of file types to which the DLP policy rule must be applied. For the complete list of supported file types refer to the  [ZIA API documentation](https://help.zscaler.com/zia/data-loss-prevention#/webDlpRules-post)
        /// </summary>
        public InputList<string> FileTypes
        {
            get => _fileTypes ?? (_fileTypes = new InputList<string>());
            set => _fileTypes = value;
        }

        /// <summary>
        /// The Name-ID pairs of groups to which the DLP policy rule must be applied. Maximum of up to `8` groups. When not used it implies `Any` to apply the rule to all groups.
        /// </summary>
        [Input("groups")]
        public Input<Inputs.ZIADLPWebRulesGroupsGetArgs>? Groups { get; set; }

        /// <summary>
        /// The DLP server, using ICAP, to which the transaction content is forwarded.
        /// </summary>
        [Input("icapServer")]
        public Input<Inputs.ZIADLPWebRulesIcapServerGetArgs>? IcapServer { get; set; }

        /// <summary>
        /// The Name-ID pairs of rule labels associated to the DLP policy rule.
        /// </summary>
        [Input("labels")]
        public Input<Inputs.ZIADLPWebRulesLabelsGetArgs>? Labels { get; set; }

        /// <summary>
        /// The Name-ID pairs of locations groups to which the DLP policy rule must be applied. Maximum of up to `32` location groups. When not used it implies `Any` to apply the rule to all location groups.
        /// </summary>
        [Input("locationGroups")]
        public Input<Inputs.ZIADLPWebRulesLocationGroupsGetArgs>? LocationGroups { get; set; }

        /// <summary>
        /// The Name-ID pairs of locations to which the DLP policy rule must be applied. Maximum of up to `8` locations. When not used it implies `Any` to apply the rule to all locations.
        /// </summary>
        [Input("locations")]
        public Input<Inputs.ZIADLPWebRulesLocationsGetArgs>? Locations { get; set; }

        /// <summary>
        /// The match only criteria for DLP engines.
        /// </summary>
        [Input("matchOnly")]
        public Input<bool>? MatchOnly { get; set; }

        /// <summary>
        /// The minimum file size (in KB) used for evaluation of the DLP policy rule.
        /// </summary>
        [Input("minSize")]
        public Input<int>? MinSize { get; set; }

        /// <summary>
        /// The DLP policy rule name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The template used for DLP notification emails.
        /// </summary>
        [Input("notificationTemplate")]
        public Input<Inputs.ZIADLPWebRulesNotificationTemplateGetArgs>? NotificationTemplate { get; set; }

        /// <summary>
        /// Enables or disables image file scanning.
        /// </summary>
        [Input("ocrEnabled")]
        public Input<bool>? OcrEnabled { get; set; }

        /// <summary>
        /// The rule order of execution for the DLP policy rule with respect to other rules.
        /// </summary>
        [Input("order")]
        public Input<int>? Order { get; set; }

        [Input("protocols")]
        private InputList<string>? _protocols;

        /// <summary>
        /// The protocol criteria specified for the DLP policy rule.
        /// </summary>
        public InputList<string> Protocols
        {
            get => _protocols ?? (_protocols = new InputList<string>());
            set => _protocols = value;
        }

        /// <summary>
        /// Admin rank of the admin who creates this rule
        /// </summary>
        [Input("rank")]
        public Input<int>? Rank { get; set; }

        [Input("ruleId")]
        public Input<int>? RuleId { get; set; }

        /// <summary>
        /// Enables or disables the DLP policy rule.. The supported values are:
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The Name-ID pairs of time windows to which the DLP policy rule must be applied. Maximum of up to `2` time intervals. When not used it implies `always` to apply the rule to all time intervals.
        /// </summary>
        [Input("timeWindows")]
        public Input<Inputs.ZIADLPWebRulesTimeWindowsGetArgs>? TimeWindows { get; set; }

        /// <summary>
        /// The list of URL categories to which the DLP policy rule must be applied.
        /// </summary>
        [Input("urlCategories")]
        public Input<Inputs.ZIADLPWebRulesUrlCategoriesGetArgs>? UrlCategories { get; set; }

        /// <summary>
        /// The Name-ID pairs of users to which the DLP policy rule must be applied. Maximum of up to `4` users. When not used it implies `Any` to apply the rule to all users.
        /// </summary>
        [Input("users")]
        public Input<Inputs.ZIADLPWebRulesUsersGetArgs>? Users { get; set; }

        /// <summary>
        /// Indicates a DLP policy rule without content inspection, when the value is set to true.
        /// </summary>
        [Input("withoutContentInspection")]
        public Input<bool>? WithoutContentInspection { get; set; }

        /// <summary>
        /// Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule.
        /// </summary>
        [Input("zscalerIncidentReciever")]
        public Input<bool>? ZscalerIncidentReciever { get; set; }

        public ZIADLPWebRulesState()
        {
        }
        public static new ZIADLPWebRulesState Empty => new ZIADLPWebRulesState();
    }
}
