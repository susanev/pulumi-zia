// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The **zia_dlp_notification_templates** resource allows the creation and management of ZIA DLP Notification Templates in the Zscaler Internet Access cloud or via the API.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"fmt"
//	"io/ioutil"
//
//	"github.com/pulumi/pulumi-zia/sdk/go/zia"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func readFileOrPanic(path string) pulumi.StringPtrInput {
//		data, err := ioutil.ReadFile(path)
//		if err != nil {
//			panic(err.Error())
//		}
//		return pulumi.String(string(data))
//	}
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := zia.NewZIADLPNotificationTemplates(ctx, "example", &zia.ZIADLPNotificationTemplatesArgs{
//				Subject:          pulumi.String(fmt.Sprintf("DLP Violation: %v %v", TRANSACTION_ID, ENGINES)),
//				AttachContent:    pulumi.Bool(true),
//				TlsEnabled:       pulumi.Bool(true),
//				HtmlMessage:      readFileOrPanic("./index.html"),
//				PlainTextMessage: readFileOrPanic("./dlp.txt"),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
type ZIADLPNotificationTemplates struct {
	pulumi.CustomResourceState

	// If set to true, the content that is violation is attached to the DLP notification email.
	AttachContent pulumi.BoolPtrOutput `pulumi:"attachContent"`
	// The template for the HTML message body that must be displayed in the DLP notification email.
	HtmlMessage pulumi.StringOutput `pulumi:"htmlMessage"`
	// The DLP policy rule name.
	Name pulumi.StringOutput `pulumi:"name"`
	// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
	PlainTextMessage pulumi.StringOutput `pulumi:"plainTextMessage"`
	// The Subject line that is displayed within the DLP notification email.
	Subject    pulumi.StringPtrOutput `pulumi:"subject"`
	TemplateId pulumi.IntOutput       `pulumi:"templateId"`
	// If set to true, the content that is violation is attached to the DLP notification email.
	TlsEnabled pulumi.BoolPtrOutput `pulumi:"tlsEnabled"`
}

// NewZIADLPNotificationTemplates registers a new resource with the given unique name, arguments, and options.
func NewZIADLPNotificationTemplates(ctx *pulumi.Context,
	name string, args *ZIADLPNotificationTemplatesArgs, opts ...pulumi.ResourceOption) (*ZIADLPNotificationTemplates, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.HtmlMessage == nil {
		return nil, errors.New("invalid value for required argument 'HtmlMessage'")
	}
	if args.PlainTextMessage == nil {
		return nil, errors.New("invalid value for required argument 'PlainTextMessage'")
	}
	opts = pkgResourceDefaultOpts(opts)
	var resource ZIADLPNotificationTemplates
	err := ctx.RegisterResource("zia:index/zIADLPNotificationTemplates:ZIADLPNotificationTemplates", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetZIADLPNotificationTemplates gets an existing ZIADLPNotificationTemplates resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetZIADLPNotificationTemplates(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ZIADLPNotificationTemplatesState, opts ...pulumi.ResourceOption) (*ZIADLPNotificationTemplates, error) {
	var resource ZIADLPNotificationTemplates
	err := ctx.ReadResource("zia:index/zIADLPNotificationTemplates:ZIADLPNotificationTemplates", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ZIADLPNotificationTemplates resources.
type ziadlpnotificationTemplatesState struct {
	// If set to true, the content that is violation is attached to the DLP notification email.
	AttachContent *bool `pulumi:"attachContent"`
	// The template for the HTML message body that must be displayed in the DLP notification email.
	HtmlMessage *string `pulumi:"htmlMessage"`
	// The DLP policy rule name.
	Name *string `pulumi:"name"`
	// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
	PlainTextMessage *string `pulumi:"plainTextMessage"`
	// The Subject line that is displayed within the DLP notification email.
	Subject    *string `pulumi:"subject"`
	TemplateId *int    `pulumi:"templateId"`
	// If set to true, the content that is violation is attached to the DLP notification email.
	TlsEnabled *bool `pulumi:"tlsEnabled"`
}

type ZIADLPNotificationTemplatesState struct {
	// If set to true, the content that is violation is attached to the DLP notification email.
	AttachContent pulumi.BoolPtrInput
	// The template for the HTML message body that must be displayed in the DLP notification email.
	HtmlMessage pulumi.StringPtrInput
	// The DLP policy rule name.
	Name pulumi.StringPtrInput
	// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
	PlainTextMessage pulumi.StringPtrInput
	// The Subject line that is displayed within the DLP notification email.
	Subject    pulumi.StringPtrInput
	TemplateId pulumi.IntPtrInput
	// If set to true, the content that is violation is attached to the DLP notification email.
	TlsEnabled pulumi.BoolPtrInput
}

func (ZIADLPNotificationTemplatesState) ElementType() reflect.Type {
	return reflect.TypeOf((*ziadlpnotificationTemplatesState)(nil)).Elem()
}

type ziadlpnotificationTemplatesArgs struct {
	// If set to true, the content that is violation is attached to the DLP notification email.
	AttachContent *bool `pulumi:"attachContent"`
	// The template for the HTML message body that must be displayed in the DLP notification email.
	HtmlMessage string `pulumi:"htmlMessage"`
	// The DLP policy rule name.
	Name *string `pulumi:"name"`
	// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
	PlainTextMessage string `pulumi:"plainTextMessage"`
	// The Subject line that is displayed within the DLP notification email.
	Subject *string `pulumi:"subject"`
	// If set to true, the content that is violation is attached to the DLP notification email.
	TlsEnabled *bool `pulumi:"tlsEnabled"`
}

// The set of arguments for constructing a ZIADLPNotificationTemplates resource.
type ZIADLPNotificationTemplatesArgs struct {
	// If set to true, the content that is violation is attached to the DLP notification email.
	AttachContent pulumi.BoolPtrInput
	// The template for the HTML message body that must be displayed in the DLP notification email.
	HtmlMessage pulumi.StringInput
	// The DLP policy rule name.
	Name pulumi.StringPtrInput
	// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
	PlainTextMessage pulumi.StringInput
	// The Subject line that is displayed within the DLP notification email.
	Subject pulumi.StringPtrInput
	// If set to true, the content that is violation is attached to the DLP notification email.
	TlsEnabled pulumi.BoolPtrInput
}

func (ZIADLPNotificationTemplatesArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ziadlpnotificationTemplatesArgs)(nil)).Elem()
}

type ZIADLPNotificationTemplatesInput interface {
	pulumi.Input

	ToZIADLPNotificationTemplatesOutput() ZIADLPNotificationTemplatesOutput
	ToZIADLPNotificationTemplatesOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesOutput
}

func (*ZIADLPNotificationTemplates) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIADLPNotificationTemplates)(nil)).Elem()
}

func (i *ZIADLPNotificationTemplates) ToZIADLPNotificationTemplatesOutput() ZIADLPNotificationTemplatesOutput {
	return i.ToZIADLPNotificationTemplatesOutputWithContext(context.Background())
}

func (i *ZIADLPNotificationTemplates) ToZIADLPNotificationTemplatesOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIADLPNotificationTemplatesOutput)
}

// ZIADLPNotificationTemplatesArrayInput is an input type that accepts ZIADLPNotificationTemplatesArray and ZIADLPNotificationTemplatesArrayOutput values.
// You can construct a concrete instance of `ZIADLPNotificationTemplatesArrayInput` via:
//
//	ZIADLPNotificationTemplatesArray{ ZIADLPNotificationTemplatesArgs{...} }
type ZIADLPNotificationTemplatesArrayInput interface {
	pulumi.Input

	ToZIADLPNotificationTemplatesArrayOutput() ZIADLPNotificationTemplatesArrayOutput
	ToZIADLPNotificationTemplatesArrayOutputWithContext(context.Context) ZIADLPNotificationTemplatesArrayOutput
}

type ZIADLPNotificationTemplatesArray []ZIADLPNotificationTemplatesInput

func (ZIADLPNotificationTemplatesArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIADLPNotificationTemplates)(nil)).Elem()
}

func (i ZIADLPNotificationTemplatesArray) ToZIADLPNotificationTemplatesArrayOutput() ZIADLPNotificationTemplatesArrayOutput {
	return i.ToZIADLPNotificationTemplatesArrayOutputWithContext(context.Background())
}

func (i ZIADLPNotificationTemplatesArray) ToZIADLPNotificationTemplatesArrayOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIADLPNotificationTemplatesArrayOutput)
}

// ZIADLPNotificationTemplatesMapInput is an input type that accepts ZIADLPNotificationTemplatesMap and ZIADLPNotificationTemplatesMapOutput values.
// You can construct a concrete instance of `ZIADLPNotificationTemplatesMapInput` via:
//
//	ZIADLPNotificationTemplatesMap{ "key": ZIADLPNotificationTemplatesArgs{...} }
type ZIADLPNotificationTemplatesMapInput interface {
	pulumi.Input

	ToZIADLPNotificationTemplatesMapOutput() ZIADLPNotificationTemplatesMapOutput
	ToZIADLPNotificationTemplatesMapOutputWithContext(context.Context) ZIADLPNotificationTemplatesMapOutput
}

type ZIADLPNotificationTemplatesMap map[string]ZIADLPNotificationTemplatesInput

func (ZIADLPNotificationTemplatesMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIADLPNotificationTemplates)(nil)).Elem()
}

func (i ZIADLPNotificationTemplatesMap) ToZIADLPNotificationTemplatesMapOutput() ZIADLPNotificationTemplatesMapOutput {
	return i.ToZIADLPNotificationTemplatesMapOutputWithContext(context.Background())
}

func (i ZIADLPNotificationTemplatesMap) ToZIADLPNotificationTemplatesMapOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIADLPNotificationTemplatesMapOutput)
}

type ZIADLPNotificationTemplatesOutput struct{ *pulumi.OutputState }

func (ZIADLPNotificationTemplatesOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIADLPNotificationTemplates)(nil)).Elem()
}

func (o ZIADLPNotificationTemplatesOutput) ToZIADLPNotificationTemplatesOutput() ZIADLPNotificationTemplatesOutput {
	return o
}

func (o ZIADLPNotificationTemplatesOutput) ToZIADLPNotificationTemplatesOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesOutput {
	return o
}

// If set to true, the content that is violation is attached to the DLP notification email.
func (o ZIADLPNotificationTemplatesOutput) AttachContent() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.BoolPtrOutput { return v.AttachContent }).(pulumi.BoolPtrOutput)
}

// The template for the HTML message body that must be displayed in the DLP notification email.
func (o ZIADLPNotificationTemplatesOutput) HtmlMessage() pulumi.StringOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.StringOutput { return v.HtmlMessage }).(pulumi.StringOutput)
}

// The DLP policy rule name.
func (o ZIADLPNotificationTemplatesOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The template for the plain text UTF-8 message body that must be displayed in the DLP notification email.
func (o ZIADLPNotificationTemplatesOutput) PlainTextMessage() pulumi.StringOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.StringOutput { return v.PlainTextMessage }).(pulumi.StringOutput)
}

// The Subject line that is displayed within the DLP notification email.
func (o ZIADLPNotificationTemplatesOutput) Subject() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.StringPtrOutput { return v.Subject }).(pulumi.StringPtrOutput)
}

func (o ZIADLPNotificationTemplatesOutput) TemplateId() pulumi.IntOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.IntOutput { return v.TemplateId }).(pulumi.IntOutput)
}

// If set to true, the content that is violation is attached to the DLP notification email.
func (o ZIADLPNotificationTemplatesOutput) TlsEnabled() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *ZIADLPNotificationTemplates) pulumi.BoolPtrOutput { return v.TlsEnabled }).(pulumi.BoolPtrOutput)
}

type ZIADLPNotificationTemplatesArrayOutput struct{ *pulumi.OutputState }

func (ZIADLPNotificationTemplatesArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIADLPNotificationTemplates)(nil)).Elem()
}

func (o ZIADLPNotificationTemplatesArrayOutput) ToZIADLPNotificationTemplatesArrayOutput() ZIADLPNotificationTemplatesArrayOutput {
	return o
}

func (o ZIADLPNotificationTemplatesArrayOutput) ToZIADLPNotificationTemplatesArrayOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesArrayOutput {
	return o
}

func (o ZIADLPNotificationTemplatesArrayOutput) Index(i pulumi.IntInput) ZIADLPNotificationTemplatesOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ZIADLPNotificationTemplates {
		return vs[0].([]*ZIADLPNotificationTemplates)[vs[1].(int)]
	}).(ZIADLPNotificationTemplatesOutput)
}

type ZIADLPNotificationTemplatesMapOutput struct{ *pulumi.OutputState }

func (ZIADLPNotificationTemplatesMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIADLPNotificationTemplates)(nil)).Elem()
}

func (o ZIADLPNotificationTemplatesMapOutput) ToZIADLPNotificationTemplatesMapOutput() ZIADLPNotificationTemplatesMapOutput {
	return o
}

func (o ZIADLPNotificationTemplatesMapOutput) ToZIADLPNotificationTemplatesMapOutputWithContext(ctx context.Context) ZIADLPNotificationTemplatesMapOutput {
	return o
}

func (o ZIADLPNotificationTemplatesMapOutput) MapIndex(k pulumi.StringInput) ZIADLPNotificationTemplatesOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ZIADLPNotificationTemplates {
		return vs[0].(map[string]*ZIADLPNotificationTemplates)[vs[1].(string)]
	}).(ZIADLPNotificationTemplatesOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ZIADLPNotificationTemplatesInput)(nil)).Elem(), &ZIADLPNotificationTemplates{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIADLPNotificationTemplatesArrayInput)(nil)).Elem(), ZIADLPNotificationTemplatesArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIADLPNotificationTemplatesMapInput)(nil)).Elem(), ZIADLPNotificationTemplatesMap{})
	pulumi.RegisterOutputType(ZIADLPNotificationTemplatesOutput{})
	pulumi.RegisterOutputType(ZIADLPNotificationTemplatesArrayOutput{})
	pulumi.RegisterOutputType(ZIADLPNotificationTemplatesMapOutput{})
}
