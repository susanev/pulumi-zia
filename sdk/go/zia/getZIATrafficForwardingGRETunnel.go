// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func LookupZIATrafficForwardingGRETunnel(ctx *pulumi.Context, args *LookupZIATrafficForwardingGRETunnelArgs, opts ...pulumi.InvokeOption) (*LookupZIATrafficForwardingGRETunnelResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv LookupZIATrafficForwardingGRETunnelResult
	err := ctx.Invoke("zia:index/getZIATrafficForwardingGRETunnel:getZIATrafficForwardingGRETunnel", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getZIATrafficForwardingGRETunnel.
type LookupZIATrafficForwardingGRETunnelArgs struct {
	Id       *int    `pulumi:"id"`
	SourceIp *string `pulumi:"sourceIp"`
}

// A collection of values returned by getZIATrafficForwardingGRETunnel.
type LookupZIATrafficForwardingGRETunnelResult struct {
	Comment              string                                             `pulumi:"comment"`
	Id                   *int                                               `pulumi:"id"`
	InternalIpRange      string                                             `pulumi:"internalIpRange"`
	IpUnnumbered         bool                                               `pulumi:"ipUnnumbered"`
	LastModificationTime int                                                `pulumi:"lastModificationTime"`
	LastModifiedBies     []GetZIATrafficForwardingGRETunnelLastModifiedBy   `pulumi:"lastModifiedBies"`
	ManagedBies          []GetZIATrafficForwardingGRETunnelManagedBy        `pulumi:"managedBies"`
	PrimaryDestVips      []GetZIATrafficForwardingGRETunnelPrimaryDestVip   `pulumi:"primaryDestVips"`
	SecondaryDestVips    []GetZIATrafficForwardingGRETunnelSecondaryDestVip `pulumi:"secondaryDestVips"`
	SourceIp             *string                                            `pulumi:"sourceIp"`
	WithinCountry        bool                                               `pulumi:"withinCountry"`
}

func LookupZIATrafficForwardingGRETunnelOutput(ctx *pulumi.Context, args LookupZIATrafficForwardingGRETunnelOutputArgs, opts ...pulumi.InvokeOption) LookupZIATrafficForwardingGRETunnelResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupZIATrafficForwardingGRETunnelResult, error) {
			args := v.(LookupZIATrafficForwardingGRETunnelArgs)
			r, err := LookupZIATrafficForwardingGRETunnel(ctx, &args, opts...)
			var s LookupZIATrafficForwardingGRETunnelResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupZIATrafficForwardingGRETunnelResultOutput)
}

// A collection of arguments for invoking getZIATrafficForwardingGRETunnel.
type LookupZIATrafficForwardingGRETunnelOutputArgs struct {
	Id       pulumi.IntPtrInput    `pulumi:"id"`
	SourceIp pulumi.StringPtrInput `pulumi:"sourceIp"`
}

func (LookupZIATrafficForwardingGRETunnelOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupZIATrafficForwardingGRETunnelArgs)(nil)).Elem()
}

// A collection of values returned by getZIATrafficForwardingGRETunnel.
type LookupZIATrafficForwardingGRETunnelResultOutput struct{ *pulumi.OutputState }

func (LookupZIATrafficForwardingGRETunnelResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupZIATrafficForwardingGRETunnelResult)(nil)).Elem()
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) ToLookupZIATrafficForwardingGRETunnelResultOutput() LookupZIATrafficForwardingGRETunnelResultOutput {
	return o
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) ToLookupZIATrafficForwardingGRETunnelResultOutputWithContext(ctx context.Context) LookupZIATrafficForwardingGRETunnelResultOutput {
	return o
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) Comment() pulumi.StringOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) string { return v.Comment }).(pulumi.StringOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) Id() pulumi.IntPtrOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) *int { return v.Id }).(pulumi.IntPtrOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) InternalIpRange() pulumi.StringOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) string { return v.InternalIpRange }).(pulumi.StringOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) IpUnnumbered() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) bool { return v.IpUnnumbered }).(pulumi.BoolOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) LastModificationTime() pulumi.IntOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) int { return v.LastModificationTime }).(pulumi.IntOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) LastModifiedBies() GetZIATrafficForwardingGRETunnelLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) []GetZIATrafficForwardingGRETunnelLastModifiedBy {
		return v.LastModifiedBies
	}).(GetZIATrafficForwardingGRETunnelLastModifiedByArrayOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) ManagedBies() GetZIATrafficForwardingGRETunnelManagedByArrayOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) []GetZIATrafficForwardingGRETunnelManagedBy {
		return v.ManagedBies
	}).(GetZIATrafficForwardingGRETunnelManagedByArrayOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) PrimaryDestVips() GetZIATrafficForwardingGRETunnelPrimaryDestVipArrayOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) []GetZIATrafficForwardingGRETunnelPrimaryDestVip {
		return v.PrimaryDestVips
	}).(GetZIATrafficForwardingGRETunnelPrimaryDestVipArrayOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) SecondaryDestVips() GetZIATrafficForwardingGRETunnelSecondaryDestVipArrayOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) []GetZIATrafficForwardingGRETunnelSecondaryDestVip {
		return v.SecondaryDestVips
	}).(GetZIATrafficForwardingGRETunnelSecondaryDestVipArrayOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) SourceIp() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) *string { return v.SourceIp }).(pulumi.StringPtrOutput)
}

func (o LookupZIATrafficForwardingGRETunnelResultOutput) WithinCountry() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupZIATrafficForwardingGRETunnelResult) bool { return v.WithinCountry }).(pulumi.BoolOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupZIATrafficForwardingGRETunnelResultOutput{})
}