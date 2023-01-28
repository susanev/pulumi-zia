// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_firewall_filtering_time_window** data source to get information about a time window option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
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
//			_, err := zia.GetZIATimeWindow(ctx, &zia.GetZIATimeWindowArgs{
//				Name: pulumi.StringRef("Work hours"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
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
//			_, err := zia.GetZIATimeWindow(ctx, &zia.GetZIATimeWindowArgs{
//				Name: pulumi.StringRef("Weekends"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
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
//			_, err := zia.GetZIATimeWindow(ctx, &zia.GetZIATimeWindowArgs{
//				Name: pulumi.StringRef("Off hours"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetZIATimeWindow(ctx *pulumi.Context, args *GetZIATimeWindowArgs, opts ...pulumi.InvokeOption) (*GetZIATimeWindowResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv GetZIATimeWindowResult
	err := ctx.Invoke("zia:index/getZIATimeWindow:getZIATimeWindow", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getZIATimeWindow.
type GetZIATimeWindowArgs struct {
	// The name of the time window to be exported.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getZIATimeWindow.
type GetZIATimeWindowResult struct {
	// (String). The supported values are:
	DayOfWeeks []string `pulumi:"dayOfWeeks"`
	// (String)
	EndTime int     `pulumi:"endTime"`
	Id      int     `pulumi:"id"`
	Name    *string `pulumi:"name"`
	// (String)
	StartTime int `pulumi:"startTime"`
}

func GetZIATimeWindowOutput(ctx *pulumi.Context, args GetZIATimeWindowOutputArgs, opts ...pulumi.InvokeOption) GetZIATimeWindowResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetZIATimeWindowResult, error) {
			args := v.(GetZIATimeWindowArgs)
			r, err := GetZIATimeWindow(ctx, &args, opts...)
			var s GetZIATimeWindowResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetZIATimeWindowResultOutput)
}

// A collection of arguments for invoking getZIATimeWindow.
type GetZIATimeWindowOutputArgs struct {
	// The name of the time window to be exported.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetZIATimeWindowOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetZIATimeWindowArgs)(nil)).Elem()
}

// A collection of values returned by getZIATimeWindow.
type GetZIATimeWindowResultOutput struct{ *pulumi.OutputState }

func (GetZIATimeWindowResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetZIATimeWindowResult)(nil)).Elem()
}

func (o GetZIATimeWindowResultOutput) ToGetZIATimeWindowResultOutput() GetZIATimeWindowResultOutput {
	return o
}

func (o GetZIATimeWindowResultOutput) ToGetZIATimeWindowResultOutputWithContext(ctx context.Context) GetZIATimeWindowResultOutput {
	return o
}

// (String). The supported values are:
func (o GetZIATimeWindowResultOutput) DayOfWeeks() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetZIATimeWindowResult) []string { return v.DayOfWeeks }).(pulumi.StringArrayOutput)
}

// (String)
func (o GetZIATimeWindowResultOutput) EndTime() pulumi.IntOutput {
	return o.ApplyT(func(v GetZIATimeWindowResult) int { return v.EndTime }).(pulumi.IntOutput)
}

func (o GetZIATimeWindowResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v GetZIATimeWindowResult) int { return v.Id }).(pulumi.IntOutput)
}

func (o GetZIATimeWindowResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetZIATimeWindowResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// (String)
func (o GetZIATimeWindowResultOutput) StartTime() pulumi.IntOutput {
	return o.ApplyT(func(v GetZIATimeWindowResult) int { return v.StartTime }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetZIATimeWindowResultOutput{})
}