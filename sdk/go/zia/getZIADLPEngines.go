// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_dlp_engines** data source to get information about a ZIA DLP Engines in the Zscaler Internet Access cloud or via the API.
func GetZIADLPEngines(ctx *pulumi.Context, args *GetZIADLPEnginesArgs, opts ...pulumi.InvokeOption) (*GetZIADLPEnginesResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv GetZIADLPEnginesResult
	err := ctx.Invoke("zia:index/getZIADLPEngines:getZIADLPEngines", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getZIADLPEngines.
type GetZIADLPEnginesArgs struct {
	// The DLP engine name as configured by the admin. This attribute is required in POST and PUT requests for custom DLP engines.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getZIADLPEngines.
type GetZIADLPEnginesResult struct {
	CustomDlpEngine      bool    `pulumi:"customDlpEngine"`
	Description          string  `pulumi:"description"`
	EngineExpression     string  `pulumi:"engineExpression"`
	Id                   int     `pulumi:"id"`
	Name                 *string `pulumi:"name"`
	PredefinedEngineName string  `pulumi:"predefinedEngineName"`
}

func GetZIADLPEnginesOutput(ctx *pulumi.Context, args GetZIADLPEnginesOutputArgs, opts ...pulumi.InvokeOption) GetZIADLPEnginesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetZIADLPEnginesResult, error) {
			args := v.(GetZIADLPEnginesArgs)
			r, err := GetZIADLPEngines(ctx, &args, opts...)
			var s GetZIADLPEnginesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetZIADLPEnginesResultOutput)
}

// A collection of arguments for invoking getZIADLPEngines.
type GetZIADLPEnginesOutputArgs struct {
	// The DLP engine name as configured by the admin. This attribute is required in POST and PUT requests for custom DLP engines.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetZIADLPEnginesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetZIADLPEnginesArgs)(nil)).Elem()
}

// A collection of values returned by getZIADLPEngines.
type GetZIADLPEnginesResultOutput struct{ *pulumi.OutputState }

func (GetZIADLPEnginesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetZIADLPEnginesResult)(nil)).Elem()
}

func (o GetZIADLPEnginesResultOutput) ToGetZIADLPEnginesResultOutput() GetZIADLPEnginesResultOutput {
	return o
}

func (o GetZIADLPEnginesResultOutput) ToGetZIADLPEnginesResultOutputWithContext(ctx context.Context) GetZIADLPEnginesResultOutput {
	return o
}

func (o GetZIADLPEnginesResultOutput) CustomDlpEngine() pulumi.BoolOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) bool { return v.CustomDlpEngine }).(pulumi.BoolOutput)
}

func (o GetZIADLPEnginesResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) string { return v.Description }).(pulumi.StringOutput)
}

func (o GetZIADLPEnginesResultOutput) EngineExpression() pulumi.StringOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) string { return v.EngineExpression }).(pulumi.StringOutput)
}

func (o GetZIADLPEnginesResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) int { return v.Id }).(pulumi.IntOutput)
}

func (o GetZIADLPEnginesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetZIADLPEnginesResultOutput) PredefinedEngineName() pulumi.StringOutput {
	return o.ApplyT(func(v GetZIADLPEnginesResult) string { return v.PredefinedEngineName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetZIADLPEnginesResultOutput{})
}