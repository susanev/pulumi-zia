// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The **zia_rule_labels** resource allows the creation and management of rule labels in the Zscaler Internet Access cloud or via the API. This resource can then be associated with resources such as: Firewall Rules and URL filtering rules
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
//			_, err := zia.NewZIARuleLabels(ctx, "example", &zia.ZIARuleLabelsArgs{
//				Description: pulumi.String("Example"),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
type ZIARuleLabels struct {
	pulumi.CustomResourceState

	// The admin that created the rule label. This is a read-only field. Ignored by PUT requests.
	CreatedBies ZIARuleLabelsCreatedByArrayOutput `pulumi:"createdBies"`
	// The rule label description.
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The admin that modified the rule label last. This is a read-only field. Ignored by PUT requests.
	LastModifiedBies ZIARuleLabelsLastModifiedByArrayOutput `pulumi:"lastModifiedBies"`
	// Timestamp when the rule lable was last modified. This is a read-only field. Ignored by PUT and DELETE requests.
	LastModifiedTime pulumi.IntOutput `pulumi:"lastModifiedTime"`
	// The name of the devices to be created.
	Name                pulumi.StringOutput `pulumi:"name"`
	ReferencedRuleCount pulumi.IntOutput    `pulumi:"referencedRuleCount"`
	RuleLabelId         pulumi.IntOutput    `pulumi:"ruleLabelId"`
}

// NewZIARuleLabels registers a new resource with the given unique name, arguments, and options.
func NewZIARuleLabels(ctx *pulumi.Context,
	name string, args *ZIARuleLabelsArgs, opts ...pulumi.ResourceOption) (*ZIARuleLabels, error) {
	if args == nil {
		args = &ZIARuleLabelsArgs{}
	}

	opts = pkgResourceDefaultOpts(opts)
	var resource ZIARuleLabels
	err := ctx.RegisterResource("zia:index/zIARuleLabels:ZIARuleLabels", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetZIARuleLabels gets an existing ZIARuleLabels resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetZIARuleLabels(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ZIARuleLabelsState, opts ...pulumi.ResourceOption) (*ZIARuleLabels, error) {
	var resource ZIARuleLabels
	err := ctx.ReadResource("zia:index/zIARuleLabels:ZIARuleLabels", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ZIARuleLabels resources.
type ziaruleLabelsState struct {
	// The admin that created the rule label. This is a read-only field. Ignored by PUT requests.
	CreatedBies []ZIARuleLabelsCreatedBy `pulumi:"createdBies"`
	// The rule label description.
	Description *string `pulumi:"description"`
	// The admin that modified the rule label last. This is a read-only field. Ignored by PUT requests.
	LastModifiedBies []ZIARuleLabelsLastModifiedBy `pulumi:"lastModifiedBies"`
	// Timestamp when the rule lable was last modified. This is a read-only field. Ignored by PUT and DELETE requests.
	LastModifiedTime *int `pulumi:"lastModifiedTime"`
	// The name of the devices to be created.
	Name                *string `pulumi:"name"`
	ReferencedRuleCount *int    `pulumi:"referencedRuleCount"`
	RuleLabelId         *int    `pulumi:"ruleLabelId"`
}

type ZIARuleLabelsState struct {
	// The admin that created the rule label. This is a read-only field. Ignored by PUT requests.
	CreatedBies ZIARuleLabelsCreatedByArrayInput
	// The rule label description.
	Description pulumi.StringPtrInput
	// The admin that modified the rule label last. This is a read-only field. Ignored by PUT requests.
	LastModifiedBies ZIARuleLabelsLastModifiedByArrayInput
	// Timestamp when the rule lable was last modified. This is a read-only field. Ignored by PUT and DELETE requests.
	LastModifiedTime pulumi.IntPtrInput
	// The name of the devices to be created.
	Name                pulumi.StringPtrInput
	ReferencedRuleCount pulumi.IntPtrInput
	RuleLabelId         pulumi.IntPtrInput
}

func (ZIARuleLabelsState) ElementType() reflect.Type {
	return reflect.TypeOf((*ziaruleLabelsState)(nil)).Elem()
}

type ziaruleLabelsArgs struct {
	// The rule label description.
	Description *string `pulumi:"description"`
	// The name of the devices to be created.
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a ZIARuleLabels resource.
type ZIARuleLabelsArgs struct {
	// The rule label description.
	Description pulumi.StringPtrInput
	// The name of the devices to be created.
	Name pulumi.StringPtrInput
}

func (ZIARuleLabelsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ziaruleLabelsArgs)(nil)).Elem()
}

type ZIARuleLabelsInput interface {
	pulumi.Input

	ToZIARuleLabelsOutput() ZIARuleLabelsOutput
	ToZIARuleLabelsOutputWithContext(ctx context.Context) ZIARuleLabelsOutput
}

func (*ZIARuleLabels) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIARuleLabels)(nil)).Elem()
}

func (i *ZIARuleLabels) ToZIARuleLabelsOutput() ZIARuleLabelsOutput {
	return i.ToZIARuleLabelsOutputWithContext(context.Background())
}

func (i *ZIARuleLabels) ToZIARuleLabelsOutputWithContext(ctx context.Context) ZIARuleLabelsOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIARuleLabelsOutput)
}

// ZIARuleLabelsArrayInput is an input type that accepts ZIARuleLabelsArray and ZIARuleLabelsArrayOutput values.
// You can construct a concrete instance of `ZIARuleLabelsArrayInput` via:
//
//	ZIARuleLabelsArray{ ZIARuleLabelsArgs{...} }
type ZIARuleLabelsArrayInput interface {
	pulumi.Input

	ToZIARuleLabelsArrayOutput() ZIARuleLabelsArrayOutput
	ToZIARuleLabelsArrayOutputWithContext(context.Context) ZIARuleLabelsArrayOutput
}

type ZIARuleLabelsArray []ZIARuleLabelsInput

func (ZIARuleLabelsArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIARuleLabels)(nil)).Elem()
}

func (i ZIARuleLabelsArray) ToZIARuleLabelsArrayOutput() ZIARuleLabelsArrayOutput {
	return i.ToZIARuleLabelsArrayOutputWithContext(context.Background())
}

func (i ZIARuleLabelsArray) ToZIARuleLabelsArrayOutputWithContext(ctx context.Context) ZIARuleLabelsArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIARuleLabelsArrayOutput)
}

// ZIARuleLabelsMapInput is an input type that accepts ZIARuleLabelsMap and ZIARuleLabelsMapOutput values.
// You can construct a concrete instance of `ZIARuleLabelsMapInput` via:
//
//	ZIARuleLabelsMap{ "key": ZIARuleLabelsArgs{...} }
type ZIARuleLabelsMapInput interface {
	pulumi.Input

	ToZIARuleLabelsMapOutput() ZIARuleLabelsMapOutput
	ToZIARuleLabelsMapOutputWithContext(context.Context) ZIARuleLabelsMapOutput
}

type ZIARuleLabelsMap map[string]ZIARuleLabelsInput

func (ZIARuleLabelsMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIARuleLabels)(nil)).Elem()
}

func (i ZIARuleLabelsMap) ToZIARuleLabelsMapOutput() ZIARuleLabelsMapOutput {
	return i.ToZIARuleLabelsMapOutputWithContext(context.Background())
}

func (i ZIARuleLabelsMap) ToZIARuleLabelsMapOutputWithContext(ctx context.Context) ZIARuleLabelsMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIARuleLabelsMapOutput)
}

type ZIARuleLabelsOutput struct{ *pulumi.OutputState }

func (ZIARuleLabelsOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIARuleLabels)(nil)).Elem()
}

func (o ZIARuleLabelsOutput) ToZIARuleLabelsOutput() ZIARuleLabelsOutput {
	return o
}

func (o ZIARuleLabelsOutput) ToZIARuleLabelsOutputWithContext(ctx context.Context) ZIARuleLabelsOutput {
	return o
}

// The admin that created the rule label. This is a read-only field. Ignored by PUT requests.
func (o ZIARuleLabelsOutput) CreatedBies() ZIARuleLabelsCreatedByArrayOutput {
	return o.ApplyT(func(v *ZIARuleLabels) ZIARuleLabelsCreatedByArrayOutput { return v.CreatedBies }).(ZIARuleLabelsCreatedByArrayOutput)
}

// The rule label description.
func (o ZIARuleLabelsOutput) Description() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIARuleLabels) pulumi.StringPtrOutput { return v.Description }).(pulumi.StringPtrOutput)
}

// The admin that modified the rule label last. This is a read-only field. Ignored by PUT requests.
func (o ZIARuleLabelsOutput) LastModifiedBies() ZIARuleLabelsLastModifiedByArrayOutput {
	return o.ApplyT(func(v *ZIARuleLabels) ZIARuleLabelsLastModifiedByArrayOutput { return v.LastModifiedBies }).(ZIARuleLabelsLastModifiedByArrayOutput)
}

// Timestamp when the rule lable was last modified. This is a read-only field. Ignored by PUT and DELETE requests.
func (o ZIARuleLabelsOutput) LastModifiedTime() pulumi.IntOutput {
	return o.ApplyT(func(v *ZIARuleLabels) pulumi.IntOutput { return v.LastModifiedTime }).(pulumi.IntOutput)
}

// The name of the devices to be created.
func (o ZIARuleLabelsOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *ZIARuleLabels) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

func (o ZIARuleLabelsOutput) ReferencedRuleCount() pulumi.IntOutput {
	return o.ApplyT(func(v *ZIARuleLabels) pulumi.IntOutput { return v.ReferencedRuleCount }).(pulumi.IntOutput)
}

func (o ZIARuleLabelsOutput) RuleLabelId() pulumi.IntOutput {
	return o.ApplyT(func(v *ZIARuleLabels) pulumi.IntOutput { return v.RuleLabelId }).(pulumi.IntOutput)
}

type ZIARuleLabelsArrayOutput struct{ *pulumi.OutputState }

func (ZIARuleLabelsArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIARuleLabels)(nil)).Elem()
}

func (o ZIARuleLabelsArrayOutput) ToZIARuleLabelsArrayOutput() ZIARuleLabelsArrayOutput {
	return o
}

func (o ZIARuleLabelsArrayOutput) ToZIARuleLabelsArrayOutputWithContext(ctx context.Context) ZIARuleLabelsArrayOutput {
	return o
}

func (o ZIARuleLabelsArrayOutput) Index(i pulumi.IntInput) ZIARuleLabelsOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ZIARuleLabels {
		return vs[0].([]*ZIARuleLabels)[vs[1].(int)]
	}).(ZIARuleLabelsOutput)
}

type ZIARuleLabelsMapOutput struct{ *pulumi.OutputState }

func (ZIARuleLabelsMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIARuleLabels)(nil)).Elem()
}

func (o ZIARuleLabelsMapOutput) ToZIARuleLabelsMapOutput() ZIARuleLabelsMapOutput {
	return o
}

func (o ZIARuleLabelsMapOutput) ToZIARuleLabelsMapOutputWithContext(ctx context.Context) ZIARuleLabelsMapOutput {
	return o
}

func (o ZIARuleLabelsMapOutput) MapIndex(k pulumi.StringInput) ZIARuleLabelsOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ZIARuleLabels {
		return vs[0].(map[string]*ZIARuleLabels)[vs[1].(string)]
	}).(ZIARuleLabelsOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ZIARuleLabelsInput)(nil)).Elem(), &ZIARuleLabels{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIARuleLabelsArrayInput)(nil)).Elem(), ZIARuleLabelsArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIARuleLabelsMapInput)(nil)).Elem(), ZIARuleLabelsMap{})
	pulumi.RegisterOutputType(ZIARuleLabelsOutput{})
	pulumi.RegisterOutputType(ZIARuleLabelsArrayOutput{})
	pulumi.RegisterOutputType(ZIARuleLabelsMapOutput{})
}
