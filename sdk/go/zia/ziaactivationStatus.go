// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

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
//			_, err := zia.LookupZIAActivationStatus(ctx, nil, nil)
//			if err != nil {
//				return err
//			}
//			_, err = zia.NewZIAActivationStatus(ctx, "activationIndex/zIAActivationStatusZIAActivationStatus", &zia.ZIAActivationStatusArgs{
//				Status: pulumi.String("ACTIVE"),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// Activation is not an importable resource.
type ZIAActivationStatus struct {
	pulumi.CustomResourceState

	// Activates configuration changes.
	Status pulumi.StringOutput `pulumi:"status"`
}

// NewZIAActivationStatus registers a new resource with the given unique name, arguments, and options.
func NewZIAActivationStatus(ctx *pulumi.Context,
	name string, args *ZIAActivationStatusArgs, opts ...pulumi.ResourceOption) (*ZIAActivationStatus, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Status == nil {
		return nil, errors.New("invalid value for required argument 'Status'")
	}
	opts = pkgResourceDefaultOpts(opts)
	var resource ZIAActivationStatus
	err := ctx.RegisterResource("zia:index/zIAActivationStatus:ZIAActivationStatus", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetZIAActivationStatus gets an existing ZIAActivationStatus resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetZIAActivationStatus(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ZIAActivationStatusState, opts ...pulumi.ResourceOption) (*ZIAActivationStatus, error) {
	var resource ZIAActivationStatus
	err := ctx.ReadResource("zia:index/zIAActivationStatus:ZIAActivationStatus", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ZIAActivationStatus resources.
type ziaactivationStatusState struct {
	// Activates configuration changes.
	Status *string `pulumi:"status"`
}

type ZIAActivationStatusState struct {
	// Activates configuration changes.
	Status pulumi.StringPtrInput
}

func (ZIAActivationStatusState) ElementType() reflect.Type {
	return reflect.TypeOf((*ziaactivationStatusState)(nil)).Elem()
}

type ziaactivationStatusArgs struct {
	// Activates configuration changes.
	Status string `pulumi:"status"`
}

// The set of arguments for constructing a ZIAActivationStatus resource.
type ZIAActivationStatusArgs struct {
	// Activates configuration changes.
	Status pulumi.StringInput
}

func (ZIAActivationStatusArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ziaactivationStatusArgs)(nil)).Elem()
}

type ZIAActivationStatusInput interface {
	pulumi.Input

	ToZIAActivationStatusOutput() ZIAActivationStatusOutput
	ToZIAActivationStatusOutputWithContext(ctx context.Context) ZIAActivationStatusOutput
}

func (*ZIAActivationStatus) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIAActivationStatus)(nil)).Elem()
}

func (i *ZIAActivationStatus) ToZIAActivationStatusOutput() ZIAActivationStatusOutput {
	return i.ToZIAActivationStatusOutputWithContext(context.Background())
}

func (i *ZIAActivationStatus) ToZIAActivationStatusOutputWithContext(ctx context.Context) ZIAActivationStatusOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIAActivationStatusOutput)
}

// ZIAActivationStatusArrayInput is an input type that accepts ZIAActivationStatusArray and ZIAActivationStatusArrayOutput values.
// You can construct a concrete instance of `ZIAActivationStatusArrayInput` via:
//
//	ZIAActivationStatusArray{ ZIAActivationStatusArgs{...} }
type ZIAActivationStatusArrayInput interface {
	pulumi.Input

	ToZIAActivationStatusArrayOutput() ZIAActivationStatusArrayOutput
	ToZIAActivationStatusArrayOutputWithContext(context.Context) ZIAActivationStatusArrayOutput
}

type ZIAActivationStatusArray []ZIAActivationStatusInput

func (ZIAActivationStatusArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIAActivationStatus)(nil)).Elem()
}

func (i ZIAActivationStatusArray) ToZIAActivationStatusArrayOutput() ZIAActivationStatusArrayOutput {
	return i.ToZIAActivationStatusArrayOutputWithContext(context.Background())
}

func (i ZIAActivationStatusArray) ToZIAActivationStatusArrayOutputWithContext(ctx context.Context) ZIAActivationStatusArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIAActivationStatusArrayOutput)
}

// ZIAActivationStatusMapInput is an input type that accepts ZIAActivationStatusMap and ZIAActivationStatusMapOutput values.
// You can construct a concrete instance of `ZIAActivationStatusMapInput` via:
//
//	ZIAActivationStatusMap{ "key": ZIAActivationStatusArgs{...} }
type ZIAActivationStatusMapInput interface {
	pulumi.Input

	ToZIAActivationStatusMapOutput() ZIAActivationStatusMapOutput
	ToZIAActivationStatusMapOutputWithContext(context.Context) ZIAActivationStatusMapOutput
}

type ZIAActivationStatusMap map[string]ZIAActivationStatusInput

func (ZIAActivationStatusMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIAActivationStatus)(nil)).Elem()
}

func (i ZIAActivationStatusMap) ToZIAActivationStatusMapOutput() ZIAActivationStatusMapOutput {
	return i.ToZIAActivationStatusMapOutputWithContext(context.Background())
}

func (i ZIAActivationStatusMap) ToZIAActivationStatusMapOutputWithContext(ctx context.Context) ZIAActivationStatusMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIAActivationStatusMapOutput)
}

type ZIAActivationStatusOutput struct{ *pulumi.OutputState }

func (ZIAActivationStatusOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIAActivationStatus)(nil)).Elem()
}

func (o ZIAActivationStatusOutput) ToZIAActivationStatusOutput() ZIAActivationStatusOutput {
	return o
}

func (o ZIAActivationStatusOutput) ToZIAActivationStatusOutputWithContext(ctx context.Context) ZIAActivationStatusOutput {
	return o
}

// Activates configuration changes.
func (o ZIAActivationStatusOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *ZIAActivationStatus) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

type ZIAActivationStatusArrayOutput struct{ *pulumi.OutputState }

func (ZIAActivationStatusArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIAActivationStatus)(nil)).Elem()
}

func (o ZIAActivationStatusArrayOutput) ToZIAActivationStatusArrayOutput() ZIAActivationStatusArrayOutput {
	return o
}

func (o ZIAActivationStatusArrayOutput) ToZIAActivationStatusArrayOutputWithContext(ctx context.Context) ZIAActivationStatusArrayOutput {
	return o
}

func (o ZIAActivationStatusArrayOutput) Index(i pulumi.IntInput) ZIAActivationStatusOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ZIAActivationStatus {
		return vs[0].([]*ZIAActivationStatus)[vs[1].(int)]
	}).(ZIAActivationStatusOutput)
}

type ZIAActivationStatusMapOutput struct{ *pulumi.OutputState }

func (ZIAActivationStatusMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIAActivationStatus)(nil)).Elem()
}

func (o ZIAActivationStatusMapOutput) ToZIAActivationStatusMapOutput() ZIAActivationStatusMapOutput {
	return o
}

func (o ZIAActivationStatusMapOutput) ToZIAActivationStatusMapOutputWithContext(ctx context.Context) ZIAActivationStatusMapOutput {
	return o
}

func (o ZIAActivationStatusMapOutput) MapIndex(k pulumi.StringInput) ZIAActivationStatusOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ZIAActivationStatus {
		return vs[0].(map[string]*ZIAActivationStatus)[vs[1].(string)]
	}).(ZIAActivationStatusOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ZIAActivationStatusInput)(nil)).Elem(), &ZIAActivationStatus{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIAActivationStatusArrayInput)(nil)).Elem(), ZIAActivationStatusArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIAActivationStatusMapInput)(nil)).Elem(), ZIAActivationStatusMap{})
	pulumi.RegisterOutputType(ZIAActivationStatusOutput{})
	pulumi.RegisterOutputType(ZIAActivationStatusArrayOutput{})
	pulumi.RegisterOutputType(ZIAActivationStatusMapOutput{})
}