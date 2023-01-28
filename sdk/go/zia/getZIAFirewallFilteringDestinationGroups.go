// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_firewall_filtering_destination_groups** data source to get information about IP destination groups option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-zia/sdk/go/zia"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := zia.LookupZIAFirewallFilteringDestinationGroups(ctx, &zia.LookupZIAFirewallFilteringDestinationGroupsArgs{
//				Name: pulumi.StringRef("example"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupZIAFirewallFilteringDestinationGroups(ctx *pulumi.Context, args *LookupZIAFirewallFilteringDestinationGroupsArgs, opts ...pulumi.InvokeOption) (*LookupZIAFirewallFilteringDestinationGroupsResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv LookupZIAFirewallFilteringDestinationGroupsResult
	err := ctx.Invoke("zia:index/getZIAFirewallFilteringDestinationGroups:getZIAFirewallFilteringDestinationGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getZIAFirewallFilteringDestinationGroups.
type LookupZIAFirewallFilteringDestinationGroupsArgs struct {
	// The ID of the destination group resource.
	Id *int `pulumi:"id"`
	// The name of the destination group to be exported.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getZIAFirewallFilteringDestinationGroups.
type LookupZIAFirewallFilteringDestinationGroupsResult struct {
	// (List of String) Destination IP addresses within the group
	Addresses []string `pulumi:"addresses"`
	// (List of String) Destination IP address counties. You can identify destinations based on the location of a server.
	Countries []string `pulumi:"countries"`
	// (String) Additional information about the destination IP group
	Description string `pulumi:"description"`
	Id          int    `pulumi:"id"`
	// (List of String) Destination IP address URL categories. You can identify destinations based on the URL category of the domain.
	IpCategories []string `pulumi:"ipCategories"`
	Name         string   `pulumi:"name"`
	// (String) Destination IP group type (i.e., the group can contain destination IP addresses or FQDNs)
	Type string `pulumi:"type"`
}

func LookupZIAFirewallFilteringDestinationGroupsOutput(ctx *pulumi.Context, args LookupZIAFirewallFilteringDestinationGroupsOutputArgs, opts ...pulumi.InvokeOption) LookupZIAFirewallFilteringDestinationGroupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupZIAFirewallFilteringDestinationGroupsResult, error) {
			args := v.(LookupZIAFirewallFilteringDestinationGroupsArgs)
			r, err := LookupZIAFirewallFilteringDestinationGroups(ctx, &args, opts...)
			var s LookupZIAFirewallFilteringDestinationGroupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupZIAFirewallFilteringDestinationGroupsResultOutput)
}

// A collection of arguments for invoking getZIAFirewallFilteringDestinationGroups.
type LookupZIAFirewallFilteringDestinationGroupsOutputArgs struct {
	// The ID of the destination group resource.
	Id pulumi.IntPtrInput `pulumi:"id"`
	// The name of the destination group to be exported.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (LookupZIAFirewallFilteringDestinationGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupZIAFirewallFilteringDestinationGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getZIAFirewallFilteringDestinationGroups.
type LookupZIAFirewallFilteringDestinationGroupsResultOutput struct{ *pulumi.OutputState }

func (LookupZIAFirewallFilteringDestinationGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupZIAFirewallFilteringDestinationGroupsResult)(nil)).Elem()
}

func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) ToLookupZIAFirewallFilteringDestinationGroupsResultOutput() LookupZIAFirewallFilteringDestinationGroupsResultOutput {
	return o
}

func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) ToLookupZIAFirewallFilteringDestinationGroupsResultOutputWithContext(ctx context.Context) LookupZIAFirewallFilteringDestinationGroupsResultOutput {
	return o
}

// (List of String) Destination IP addresses within the group
func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Addresses() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) []string { return v.Addresses }).(pulumi.StringArrayOutput)
}

// (List of String) Destination IP address counties. You can identify destinations based on the location of a server.
func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Countries() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) []string { return v.Countries }).(pulumi.StringArrayOutput)
}

// (String) Additional information about the destination IP group
func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) string { return v.Description }).(pulumi.StringOutput)
}

func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) int { return v.Id }).(pulumi.IntOutput)
}

// (List of String) Destination IP address URL categories. You can identify destinations based on the URL category of the domain.
func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) IpCategories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) []string { return v.IpCategories }).(pulumi.StringArrayOutput)
}

func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) string { return v.Name }).(pulumi.StringOutput)
}

// (String) Destination IP group type (i.e., the group can contain destination IP addresses or FQDNs)
func (o LookupZIAFirewallFilteringDestinationGroupsResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupZIAFirewallFilteringDestinationGroupsResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupZIAFirewallFilteringDestinationGroupsResultOutput{})
}