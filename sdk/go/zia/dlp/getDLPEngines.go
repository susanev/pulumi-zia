// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dlp

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_dlp_engines** data source to get information about a ZIA DLP Engines in the Zscaler Internet Access cloud or via the API.
func GetDLPEngines(ctx *pulumi.Context, args *GetDLPEnginesArgs, opts ...pulumi.InvokeOption) (*GetDLPEnginesResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv GetDLPEnginesResult
	err := ctx.Invoke("zia:DLP/getDLPEngines:getDLPEngines", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDLPEngines.
type GetDLPEnginesArgs struct {
	// The DLP engine name as configured by the admin. This attribute is required in POST and PUT requests for custom DLP engines.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getDLPEngines.
type GetDLPEnginesResult struct {
	CustomDlpEngine      bool    `pulumi:"customDlpEngine"`
	Description          string  `pulumi:"description"`
	EngineExpression     string  `pulumi:"engineExpression"`
	Id                   int     `pulumi:"id"`
	Name                 *string `pulumi:"name"`
	PredefinedEngineName string  `pulumi:"predefinedEngineName"`
}

func GetDLPEnginesOutput(ctx *pulumi.Context, args GetDLPEnginesOutputArgs, opts ...pulumi.InvokeOption) GetDLPEnginesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDLPEnginesResult, error) {
			args := v.(GetDLPEnginesArgs)
			r, err := GetDLPEngines(ctx, &args, opts...)
			var s GetDLPEnginesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDLPEnginesResultOutput)
}

// A collection of arguments for invoking getDLPEngines.
type GetDLPEnginesOutputArgs struct {
	// The DLP engine name as configured by the admin. This attribute is required in POST and PUT requests for custom DLP engines.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetDLPEnginesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDLPEnginesArgs)(nil)).Elem()
}

// A collection of values returned by getDLPEngines.
type GetDLPEnginesResultOutput struct{ *pulumi.OutputState }

func (GetDLPEnginesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDLPEnginesResult)(nil)).Elem()
}

func (o GetDLPEnginesResultOutput) ToGetDLPEnginesResultOutput() GetDLPEnginesResultOutput {
	return o
}

func (o GetDLPEnginesResultOutput) ToGetDLPEnginesResultOutputWithContext(ctx context.Context) GetDLPEnginesResultOutput {
	return o
}

func (o GetDLPEnginesResultOutput) CustomDlpEngine() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) bool { return v.CustomDlpEngine }).(pulumi.BoolOutput)
}

func (o GetDLPEnginesResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) string { return v.Description }).(pulumi.StringOutput)
}

func (o GetDLPEnginesResultOutput) EngineExpression() pulumi.StringOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) string { return v.EngineExpression }).(pulumi.StringOutput)
}

func (o GetDLPEnginesResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) int { return v.Id }).(pulumi.IntOutput)
}

func (o GetDLPEnginesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetDLPEnginesResultOutput) PredefinedEngineName() pulumi.StringOutput {
	return o.ApplyT(func(v GetDLPEnginesResult) string { return v.PredefinedEngineName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDLPEnginesResultOutput{})
}
