// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package urlfiltering

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_url_filtering_rules** data source to get information about a URL filtering rule information for the specified `Name`.
//
// ```go
// package main
//
// import (
//
//	"github.com/zscaler/pulumi-zia/sdk/go/zia/URLFiltering"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := URLFiltering.GetURLFilteringRules(ctx, &urlfiltering.GetURLFilteringRulesArgs{
//				Name: pulumi.StringRef("Example"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupURLFilteringRules(ctx *pulumi.Context, args *LookupURLFilteringRulesArgs, opts ...pulumi.InvokeOption) (*LookupURLFilteringRulesResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv LookupURLFilteringRulesResult
	err := ctx.Invoke("zia:URLFiltering/getURLFilteringRules:getURLFilteringRules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getURLFilteringRules.
type LookupURLFilteringRulesArgs struct {
	DeviceTrustLevels []string `pulumi:"deviceTrustLevels"`
	// URL Filtering Rule ID
	Id *int `pulumi:"id"`
	// Name of the URL Filtering policy rule
	Name *string `pulumi:"name"`
	// (Number) Order of execution of rule with respect to other URL Filtering rules
	Order          *int     `pulumi:"order"`
	UserAgentTypes []string `pulumi:"userAgentTypes"`
}

// A collection of values returned by getURLFilteringRules.
type LookupURLFilteringRulesResult struct {
	// (String) Action taken when traffic matches rule criteria. Supported values: `ANY`, `NONE`, `BLOCK`, `CAUTION`, `ALLOW`, `ICAP_RESPONSE`
	Action string `pulumi:"action"`
	// (String) When set to true, a `BLOCK` action triggered by the rule could be overridden. If true and both overrideGroup and overrideUsers are not set, the `BLOCK` triggered by this rule could be overridden for any users. If block)Override is not set, `BLOCK` action cannot be overridden.
	BlockOverride bool `pulumi:"blockOverride"`
	CbiProfileId  int  `pulumi:"cbiProfileId"`
	Ciparule      bool `pulumi:"ciparule"`
	// (List of Object) The departments to which the Firewall Filtering policy rule applies
	Departments []GetURLFilteringRulesDepartment `pulumi:"departments"`
	// (String) Additional information about the rule
	Description       string                            `pulumi:"description"`
	DeviceGroups      []GetURLFilteringRulesDeviceGroup `pulumi:"deviceGroups"`
	DeviceTrustLevels []string                          `pulumi:"deviceTrustLevels"`
	Devices           []GetURLFilteringRulesDevice      `pulumi:"devices"`
	// (String) URL of end user notification page to be displayed when the rule is matched. Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
	EndUserNotificationUrl string `pulumi:"endUserNotificationUrl"`
	// (String) Enforce a set a validity time period for the URL Filtering rule.
	EnforceTimeValidity bool `pulumi:"enforceTimeValidity"`
	// (List of Object) The groups to which the Firewall Filtering policy rule applies
	Groups []GetURLFilteringRulesGroup `pulumi:"groups"`
	// (Number) Identifier that uniquely identifies an entity
	Id               int                                  `pulumi:"id"`
	Labels           []GetURLFilteringRulesLabel          `pulumi:"labels"`
	LastModifiedBies []GetURLFilteringRulesLastModifiedBy `pulumi:"lastModifiedBies"`
	// (Number) When the rule was last modified
	LastModifiedTime int `pulumi:"lastModifiedTime"`
	// (List of Object) The location groups to which the Firewall Filtering policy rule applies
	LocationGroups []GetURLFilteringRulesLocationGroup `pulumi:"locationGroups"`
	// (List of Object) The locations to which the Firewall Filtering policy rule applies
	Locations []GetURLFilteringRulesLocation `pulumi:"locations"`
	// (String) The configured name of the entity
	Name string `pulumi:"name"`
	// (Number) Order of execution of rule with respect to other URL Filtering rules
	Order int `pulumi:"order"`
	// (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any group.
	OverrideGroups []GetURLFilteringRulesOverrideGroup `pulumi:"overrideGroups"`
	// (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any user.
	OverrideUsers []GetURLFilteringRulesOverrideUser `pulumi:"overrideUsers"`
	// (List of Object) Protocol criteria. Supported values: `SMRULEF_ZPA_BROKERS_RULE`, `ANY_RULE`, `TCP_RULE`, `UDP_RULE`, `DOHTTPS_RULE`, `TUNNELSSL_RULE`, `HTTP_PROXY`, `FOHTTP_RULE`, `FTP_RULE`, `HTTPS_RULE`, `HTTP_RULE`, `SSL_RULE`, `TUNNEL_RULE`.
	Protocols []string `pulumi:"protocols"`
	// (String) Admin rank of the admin who creates this rule
	Rank int `pulumi:"rank"`
	// (String) Request method for which the rule must be applied. If not set, rule will be applied to all methods
	RequestMethods []string `pulumi:"requestMethods"`
	// (String) Size quota in KB beyond which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
	SizeQuota int `pulumi:"sizeQuota"`
	// (String) Rule State
	State string `pulumi:"state"`
	// (String) Time quota in minutes, after which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
	TimeQuota int `pulumi:"timeQuota"`
	// (List of Object) The time interval in which the Firewall Filtering policy rule applies
	TimeWindows []GetURLFilteringRulesTimeWindow `pulumi:"timeWindows"`
	// (String) List of URL categories for which rule must be applied
	UrlCategories  []string `pulumi:"urlCategories"`
	UserAgentTypes []string `pulumi:"userAgentTypes"`
	// (List of Object) The users to which the Firewall Filtering policy rule applies
	Users []GetURLFilteringRulesUser `pulumi:"users"`
	// (Number) If enforceTimeValidity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
	ValidityEndTime int `pulumi:"validityEndTime"`
	// (Number) If enforceTimeValidity is set to true, the URL Filtering rule will be valid starting on this date and time.
	ValidityStartTime int `pulumi:"validityStartTime"`
	// (Number) If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID.
	ValidityTimeZoneId string `pulumi:"validityTimeZoneId"`
}

func LookupURLFilteringRulesOutput(ctx *pulumi.Context, args LookupURLFilteringRulesOutputArgs, opts ...pulumi.InvokeOption) LookupURLFilteringRulesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupURLFilteringRulesResult, error) {
			args := v.(LookupURLFilteringRulesArgs)
			r, err := LookupURLFilteringRules(ctx, &args, opts...)
			var s LookupURLFilteringRulesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupURLFilteringRulesResultOutput)
}

// A collection of arguments for invoking getURLFilteringRules.
type LookupURLFilteringRulesOutputArgs struct {
	DeviceTrustLevels pulumi.StringArrayInput `pulumi:"deviceTrustLevels"`
	// URL Filtering Rule ID
	Id pulumi.IntPtrInput `pulumi:"id"`
	// Name of the URL Filtering policy rule
	Name pulumi.StringPtrInput `pulumi:"name"`
	// (Number) Order of execution of rule with respect to other URL Filtering rules
	Order          pulumi.IntPtrInput      `pulumi:"order"`
	UserAgentTypes pulumi.StringArrayInput `pulumi:"userAgentTypes"`
}

func (LookupURLFilteringRulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupURLFilteringRulesArgs)(nil)).Elem()
}

// A collection of values returned by getURLFilteringRules.
type LookupURLFilteringRulesResultOutput struct{ *pulumi.OutputState }

func (LookupURLFilteringRulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupURLFilteringRulesResult)(nil)).Elem()
}

func (o LookupURLFilteringRulesResultOutput) ToLookupURLFilteringRulesResultOutput() LookupURLFilteringRulesResultOutput {
	return o
}

func (o LookupURLFilteringRulesResultOutput) ToLookupURLFilteringRulesResultOutputWithContext(ctx context.Context) LookupURLFilteringRulesResultOutput {
	return o
}

// (String) Action taken when traffic matches rule criteria. Supported values: `ANY`, `NONE`, `BLOCK`, `CAUTION`, `ALLOW`, `ICAP_RESPONSE`
func (o LookupURLFilteringRulesResultOutput) Action() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.Action }).(pulumi.StringOutput)
}

// (String) When set to true, a `BLOCK` action triggered by the rule could be overridden. If true and both overrideGroup and overrideUsers are not set, the `BLOCK` triggered by this rule could be overridden for any users. If block)Override is not set, `BLOCK` action cannot be overridden.
func (o LookupURLFilteringRulesResultOutput) BlockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) bool { return v.BlockOverride }).(pulumi.BoolOutput)
}

func (o LookupURLFilteringRulesResultOutput) CbiProfileId() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.CbiProfileId }).(pulumi.IntOutput)
}

func (o LookupURLFilteringRulesResultOutput) Ciparule() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) bool { return v.Ciparule }).(pulumi.BoolOutput)
}

// (List of Object) The departments to which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) Departments() GetURLFilteringRulesDepartmentArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesDepartment { return v.Departments }).(GetURLFilteringRulesDepartmentArrayOutput)
}

// (String) Additional information about the rule
func (o LookupURLFilteringRulesResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.Description }).(pulumi.StringOutput)
}

func (o LookupURLFilteringRulesResultOutput) DeviceGroups() GetURLFilteringRulesDeviceGroupArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesDeviceGroup { return v.DeviceGroups }).(GetURLFilteringRulesDeviceGroupArrayOutput)
}

func (o LookupURLFilteringRulesResultOutput) DeviceTrustLevels() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []string { return v.DeviceTrustLevels }).(pulumi.StringArrayOutput)
}

func (o LookupURLFilteringRulesResultOutput) Devices() GetURLFilteringRulesDeviceArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesDevice { return v.Devices }).(GetURLFilteringRulesDeviceArrayOutput)
}

// (String) URL of end user notification page to be displayed when the rule is matched. Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
func (o LookupURLFilteringRulesResultOutput) EndUserNotificationUrl() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.EndUserNotificationUrl }).(pulumi.StringOutput)
}

// (String) Enforce a set a validity time period for the URL Filtering rule.
func (o LookupURLFilteringRulesResultOutput) EnforceTimeValidity() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) bool { return v.EnforceTimeValidity }).(pulumi.BoolOutput)
}

// (List of Object) The groups to which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) Groups() GetURLFilteringRulesGroupArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesGroup { return v.Groups }).(GetURLFilteringRulesGroupArrayOutput)
}

// (Number) Identifier that uniquely identifies an entity
func (o LookupURLFilteringRulesResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.Id }).(pulumi.IntOutput)
}

func (o LookupURLFilteringRulesResultOutput) Labels() GetURLFilteringRulesLabelArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesLabel { return v.Labels }).(GetURLFilteringRulesLabelArrayOutput)
}

func (o LookupURLFilteringRulesResultOutput) LastModifiedBies() GetURLFilteringRulesLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesLastModifiedBy { return v.LastModifiedBies }).(GetURLFilteringRulesLastModifiedByArrayOutput)
}

// (Number) When the rule was last modified
func (o LookupURLFilteringRulesResultOutput) LastModifiedTime() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.LastModifiedTime }).(pulumi.IntOutput)
}

// (List of Object) The location groups to which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) LocationGroups() GetURLFilteringRulesLocationGroupArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesLocationGroup { return v.LocationGroups }).(GetURLFilteringRulesLocationGroupArrayOutput)
}

// (List of Object) The locations to which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) Locations() GetURLFilteringRulesLocationArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesLocation { return v.Locations }).(GetURLFilteringRulesLocationArrayOutput)
}

// (String) The configured name of the entity
func (o LookupURLFilteringRulesResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.Name }).(pulumi.StringOutput)
}

// (Number) Order of execution of rule with respect to other URL Filtering rules
func (o LookupURLFilteringRulesResultOutput) Order() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.Order }).(pulumi.IntOutput)
}

// (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any group.
func (o LookupURLFilteringRulesResultOutput) OverrideGroups() GetURLFilteringRulesOverrideGroupArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesOverrideGroup { return v.OverrideGroups }).(GetURLFilteringRulesOverrideGroupArrayOutput)
}

// (List of Object) Name-ID pairs of users for which this rule can be overridden. Applicable only if blockOverride is set to `true`, action is `BLOCK` and overrideGroups is not set.If this overrideUsers is not set, `BLOCK` action can be overridden for any user.
func (o LookupURLFilteringRulesResultOutput) OverrideUsers() GetURLFilteringRulesOverrideUserArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesOverrideUser { return v.OverrideUsers }).(GetURLFilteringRulesOverrideUserArrayOutput)
}

// (List of Object) Protocol criteria. Supported values: `SMRULEF_ZPA_BROKERS_RULE`, `ANY_RULE`, `TCP_RULE`, `UDP_RULE`, `DOHTTPS_RULE`, `TUNNELSSL_RULE`, `HTTP_PROXY`, `FOHTTP_RULE`, `FTP_RULE`, `HTTPS_RULE`, `HTTP_RULE`, `SSL_RULE`, `TUNNEL_RULE`.
func (o LookupURLFilteringRulesResultOutput) Protocols() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []string { return v.Protocols }).(pulumi.StringArrayOutput)
}

// (String) Admin rank of the admin who creates this rule
func (o LookupURLFilteringRulesResultOutput) Rank() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.Rank }).(pulumi.IntOutput)
}

// (String) Request method for which the rule must be applied. If not set, rule will be applied to all methods
func (o LookupURLFilteringRulesResultOutput) RequestMethods() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []string { return v.RequestMethods }).(pulumi.StringArrayOutput)
}

// (String) Size quota in KB beyond which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
func (o LookupURLFilteringRulesResultOutput) SizeQuota() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.SizeQuota }).(pulumi.IntOutput)
}

// (String) Rule State
func (o LookupURLFilteringRulesResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.State }).(pulumi.StringOutput)
}

// (String) Time quota in minutes, after which the URL Filtering rule is applied. If not set, no quota is enforced. If a policy rule action is set to `BLOCK`, this field is not applicable.
func (o LookupURLFilteringRulesResultOutput) TimeQuota() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.TimeQuota }).(pulumi.IntOutput)
}

// (List of Object) The time interval in which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) TimeWindows() GetURLFilteringRulesTimeWindowArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesTimeWindow { return v.TimeWindows }).(GetURLFilteringRulesTimeWindowArrayOutput)
}

// (String) List of URL categories for which rule must be applied
func (o LookupURLFilteringRulesResultOutput) UrlCategories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []string { return v.UrlCategories }).(pulumi.StringArrayOutput)
}

func (o LookupURLFilteringRulesResultOutput) UserAgentTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []string { return v.UserAgentTypes }).(pulumi.StringArrayOutput)
}

// (List of Object) The users to which the Firewall Filtering policy rule applies
func (o LookupURLFilteringRulesResultOutput) Users() GetURLFilteringRulesUserArrayOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) []GetURLFilteringRulesUser { return v.Users }).(GetURLFilteringRulesUserArrayOutput)
}

// (Number) If enforceTimeValidity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
func (o LookupURLFilteringRulesResultOutput) ValidityEndTime() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.ValidityEndTime }).(pulumi.IntOutput)
}

// (Number) If enforceTimeValidity is set to true, the URL Filtering rule will be valid starting on this date and time.
func (o LookupURLFilteringRulesResultOutput) ValidityStartTime() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) int { return v.ValidityStartTime }).(pulumi.IntOutput)
}

// (Number) If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID.
func (o LookupURLFilteringRulesResultOutput) ValidityTimeZoneId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLFilteringRulesResult) string { return v.ValidityTimeZoneId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupURLFilteringRulesResultOutput{})
}
