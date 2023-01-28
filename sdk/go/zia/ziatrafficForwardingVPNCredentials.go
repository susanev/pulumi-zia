// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package zia

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The **zia_traffic_forwarding_vpn_credentials** creates and manages VPN credentials that can be associated to locations. VPN is one way to route traffic from customer locations to the cloud. Site-to-site IPSec VPN credentials can be identified by the cloud through one of the following methods:
//
// * Common Name (CN) of IPSec Certificate
// * VPN User FQDN - requires VPN_SITE_TO_SITE subscription
// * VPN IP Address - requires VPN_SITE_TO_SITE subscription
// * Extended Authentication (XAUTH) or hosted mobile UserID - requires VPN_MOBILE subscription
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
//			_, err := zia.NewZIATrafficForwardingVPNCredentials(ctx, "example", &zia.ZIATrafficForwardingVPNCredentialsArgs{
//				Comments:     pulumi.String("Example"),
//				Fqdn:         pulumi.String("sjc-1-37@acme.com"),
//				PreSharedKey: pulumi.String("newPassword123!"),
//				Type:         pulumi.String("UFQDN"),
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
//			exampleZIATrafficForwardingStaticIP, err := zia.NewZIATrafficForwardingStaticIP(ctx, "exampleZIATrafficForwardingStaticIP", &zia.ZIATrafficForwardingStaticIPArgs{
//				IpAddress:   pulumi.String("1.1.1.1"),
//				RoutableIp:  pulumi.Bool(true),
//				Comment:     pulumi.String("Example"),
//				GeoOverride: pulumi.Bool(true),
//				Latitude:    -36.848461,
//				Longitude:   pulumi.Float64(174.763336),
//			})
//			if err != nil {
//				return err
//			}
//			_, err = zia.NewZIATrafficForwardingVPNCredentials(ctx, "exampleZIATrafficForwardingVPNCredentials", &zia.ZIATrafficForwardingVPNCredentialsArgs{
//				Type:         pulumi.String("IP"),
//				IpAddress:    exampleZIATrafficForwardingStaticIP.IpAddress,
//				Comments:     pulumi.String("Example"),
//				PreSharedKey: pulumi.String("newPassword123!"),
//			}, pulumi.DependsOn([]pulumi.Resource{
//				exampleZIATrafficForwardingStaticIP,
//			}))
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// > **NOTE** For VPN Credentials of Type `IP` a static IP resource must be created first.
//
// ## Import
//
// Static IP resources can be imported by using `<STATIC IP ID>` or `<IP ADDRESS>`as the import ID.
//
// ```sh
//
//	$ pulumi import zia:index/zIATrafficForwardingVPNCredentials:ZIATrafficForwardingVPNCredentials example <static_ip_id>
//
// ```
//
//	or
//
// ```sh
//
//	$ pulumi import zia:index/zIATrafficForwardingVPNCredentials:ZIATrafficForwardingVPNCredentials example <ip_address>
//
// ```
type ZIATrafficForwardingVPNCredentials struct {
	pulumi.CustomResourceState

	// Additional information about this VPN credential.
	Comments pulumi.StringPtrOutput `pulumi:"comments"`
	// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
	Fqdn pulumi.StringPtrOutput `pulumi:"fqdn"`
	// IP Address for the VON credentials. The parameter becomes required if `type = IP`
	IpAddress pulumi.StringPtrOutput `pulumi:"ipAddress"`
	// Pre-shared key. This is a required field for UFQDN and IP auth type.
	PreSharedKey pulumi.StringPtrOutput `pulumi:"preSharedKey"`
	// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
	Type           pulumi.StringPtrOutput `pulumi:"type"`
	VpnCredentalId pulumi.IntOutput       `pulumi:"vpnCredentalId"`
}

// NewZIATrafficForwardingVPNCredentials registers a new resource with the given unique name, arguments, and options.
func NewZIATrafficForwardingVPNCredentials(ctx *pulumi.Context,
	name string, args *ZIATrafficForwardingVPNCredentialsArgs, opts ...pulumi.ResourceOption) (*ZIATrafficForwardingVPNCredentials, error) {
	if args == nil {
		args = &ZIATrafficForwardingVPNCredentialsArgs{}
	}

	if args.PreSharedKey != nil {
		args.PreSharedKey = pulumi.ToSecret(args.PreSharedKey).(pulumi.StringPtrInput)
	}
	secrets := pulumi.AdditionalSecretOutputs([]string{
		"preSharedKey",
	})
	opts = append(opts, secrets)
	opts = pkgResourceDefaultOpts(opts)
	var resource ZIATrafficForwardingVPNCredentials
	err := ctx.RegisterResource("zia:index/zIATrafficForwardingVPNCredentials:ZIATrafficForwardingVPNCredentials", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetZIATrafficForwardingVPNCredentials gets an existing ZIATrafficForwardingVPNCredentials resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetZIATrafficForwardingVPNCredentials(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ZIATrafficForwardingVPNCredentialsState, opts ...pulumi.ResourceOption) (*ZIATrafficForwardingVPNCredentials, error) {
	var resource ZIATrafficForwardingVPNCredentials
	err := ctx.ReadResource("zia:index/zIATrafficForwardingVPNCredentials:ZIATrafficForwardingVPNCredentials", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ZIATrafficForwardingVPNCredentials resources.
type ziatrafficForwardingVPNCredentialsState struct {
	// Additional information about this VPN credential.
	Comments *string `pulumi:"comments"`
	// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
	Fqdn *string `pulumi:"fqdn"`
	// IP Address for the VON credentials. The parameter becomes required if `type = IP`
	IpAddress *string `pulumi:"ipAddress"`
	// Pre-shared key. This is a required field for UFQDN and IP auth type.
	PreSharedKey *string `pulumi:"preSharedKey"`
	// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
	Type           *string `pulumi:"type"`
	VpnCredentalId *int    `pulumi:"vpnCredentalId"`
}

type ZIATrafficForwardingVPNCredentialsState struct {
	// Additional information about this VPN credential.
	Comments pulumi.StringPtrInput
	// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
	Fqdn pulumi.StringPtrInput
	// IP Address for the VON credentials. The parameter becomes required if `type = IP`
	IpAddress pulumi.StringPtrInput
	// Pre-shared key. This is a required field for UFQDN and IP auth type.
	PreSharedKey pulumi.StringPtrInput
	// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
	Type           pulumi.StringPtrInput
	VpnCredentalId pulumi.IntPtrInput
}

func (ZIATrafficForwardingVPNCredentialsState) ElementType() reflect.Type {
	return reflect.TypeOf((*ziatrafficForwardingVPNCredentialsState)(nil)).Elem()
}

type ziatrafficForwardingVPNCredentialsArgs struct {
	// Additional information about this VPN credential.
	Comments *string `pulumi:"comments"`
	// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
	Fqdn *string `pulumi:"fqdn"`
	// IP Address for the VON credentials. The parameter becomes required if `type = IP`
	IpAddress *string `pulumi:"ipAddress"`
	// Pre-shared key. This is a required field for UFQDN and IP auth type.
	PreSharedKey *string `pulumi:"preSharedKey"`
	// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
	Type *string `pulumi:"type"`
}

// The set of arguments for constructing a ZIATrafficForwardingVPNCredentials resource.
type ZIATrafficForwardingVPNCredentialsArgs struct {
	// Additional information about this VPN credential.
	Comments pulumi.StringPtrInput
	// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
	Fqdn pulumi.StringPtrInput
	// IP Address for the VON credentials. The parameter becomes required if `type = IP`
	IpAddress pulumi.StringPtrInput
	// Pre-shared key. This is a required field for UFQDN and IP auth type.
	PreSharedKey pulumi.StringPtrInput
	// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
	Type pulumi.StringPtrInput
}

func (ZIATrafficForwardingVPNCredentialsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ziatrafficForwardingVPNCredentialsArgs)(nil)).Elem()
}

type ZIATrafficForwardingVPNCredentialsInput interface {
	pulumi.Input

	ToZIATrafficForwardingVPNCredentialsOutput() ZIATrafficForwardingVPNCredentialsOutput
	ToZIATrafficForwardingVPNCredentialsOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsOutput
}

func (*ZIATrafficForwardingVPNCredentials) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (i *ZIATrafficForwardingVPNCredentials) ToZIATrafficForwardingVPNCredentialsOutput() ZIATrafficForwardingVPNCredentialsOutput {
	return i.ToZIATrafficForwardingVPNCredentialsOutputWithContext(context.Background())
}

func (i *ZIATrafficForwardingVPNCredentials) ToZIATrafficForwardingVPNCredentialsOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIATrafficForwardingVPNCredentialsOutput)
}

// ZIATrafficForwardingVPNCredentialsArrayInput is an input type that accepts ZIATrafficForwardingVPNCredentialsArray and ZIATrafficForwardingVPNCredentialsArrayOutput values.
// You can construct a concrete instance of `ZIATrafficForwardingVPNCredentialsArrayInput` via:
//
//	ZIATrafficForwardingVPNCredentialsArray{ ZIATrafficForwardingVPNCredentialsArgs{...} }
type ZIATrafficForwardingVPNCredentialsArrayInput interface {
	pulumi.Input

	ToZIATrafficForwardingVPNCredentialsArrayOutput() ZIATrafficForwardingVPNCredentialsArrayOutput
	ToZIATrafficForwardingVPNCredentialsArrayOutputWithContext(context.Context) ZIATrafficForwardingVPNCredentialsArrayOutput
}

type ZIATrafficForwardingVPNCredentialsArray []ZIATrafficForwardingVPNCredentialsInput

func (ZIATrafficForwardingVPNCredentialsArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (i ZIATrafficForwardingVPNCredentialsArray) ToZIATrafficForwardingVPNCredentialsArrayOutput() ZIATrafficForwardingVPNCredentialsArrayOutput {
	return i.ToZIATrafficForwardingVPNCredentialsArrayOutputWithContext(context.Background())
}

func (i ZIATrafficForwardingVPNCredentialsArray) ToZIATrafficForwardingVPNCredentialsArrayOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIATrafficForwardingVPNCredentialsArrayOutput)
}

// ZIATrafficForwardingVPNCredentialsMapInput is an input type that accepts ZIATrafficForwardingVPNCredentialsMap and ZIATrafficForwardingVPNCredentialsMapOutput values.
// You can construct a concrete instance of `ZIATrafficForwardingVPNCredentialsMapInput` via:
//
//	ZIATrafficForwardingVPNCredentialsMap{ "key": ZIATrafficForwardingVPNCredentialsArgs{...} }
type ZIATrafficForwardingVPNCredentialsMapInput interface {
	pulumi.Input

	ToZIATrafficForwardingVPNCredentialsMapOutput() ZIATrafficForwardingVPNCredentialsMapOutput
	ToZIATrafficForwardingVPNCredentialsMapOutputWithContext(context.Context) ZIATrafficForwardingVPNCredentialsMapOutput
}

type ZIATrafficForwardingVPNCredentialsMap map[string]ZIATrafficForwardingVPNCredentialsInput

func (ZIATrafficForwardingVPNCredentialsMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (i ZIATrafficForwardingVPNCredentialsMap) ToZIATrafficForwardingVPNCredentialsMapOutput() ZIATrafficForwardingVPNCredentialsMapOutput {
	return i.ToZIATrafficForwardingVPNCredentialsMapOutputWithContext(context.Background())
}

func (i ZIATrafficForwardingVPNCredentialsMap) ToZIATrafficForwardingVPNCredentialsMapOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ZIATrafficForwardingVPNCredentialsMapOutput)
}

type ZIATrafficForwardingVPNCredentialsOutput struct{ *pulumi.OutputState }

func (ZIATrafficForwardingVPNCredentialsOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (o ZIATrafficForwardingVPNCredentialsOutput) ToZIATrafficForwardingVPNCredentialsOutput() ZIATrafficForwardingVPNCredentialsOutput {
	return o
}

func (o ZIATrafficForwardingVPNCredentialsOutput) ToZIATrafficForwardingVPNCredentialsOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsOutput {
	return o
}

// Additional information about this VPN credential.
func (o ZIATrafficForwardingVPNCredentialsOutput) Comments() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.StringPtrOutput { return v.Comments }).(pulumi.StringPtrOutput)
}

// Fully Qualified Domain Name. Applicable only to `UFQDN` or `XAUTH` (or `HOSTED_MOBILE_USERS`) auth type.
func (o ZIATrafficForwardingVPNCredentialsOutput) Fqdn() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.StringPtrOutput { return v.Fqdn }).(pulumi.StringPtrOutput)
}

// IP Address for the VON credentials. The parameter becomes required if `type = IP`
func (o ZIATrafficForwardingVPNCredentialsOutput) IpAddress() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.StringPtrOutput { return v.IpAddress }).(pulumi.StringPtrOutput)
}

// Pre-shared key. This is a required field for UFQDN and IP auth type.
func (o ZIATrafficForwardingVPNCredentialsOutput) PreSharedKey() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.StringPtrOutput { return v.PreSharedKey }).(pulumi.StringPtrOutput)
}

// VPN authentication type (i.e., how the VPN credential is sent to the server). It is not modifiable after VpnCredential is created. The supported values are: `UFQDN` and `IP`
func (o ZIATrafficForwardingVPNCredentialsOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.StringPtrOutput { return v.Type }).(pulumi.StringPtrOutput)
}

func (o ZIATrafficForwardingVPNCredentialsOutput) VpnCredentalId() pulumi.IntOutput {
	return o.ApplyT(func(v *ZIATrafficForwardingVPNCredentials) pulumi.IntOutput { return v.VpnCredentalId }).(pulumi.IntOutput)
}

type ZIATrafficForwardingVPNCredentialsArrayOutput struct{ *pulumi.OutputState }

func (ZIATrafficForwardingVPNCredentialsArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (o ZIATrafficForwardingVPNCredentialsArrayOutput) ToZIATrafficForwardingVPNCredentialsArrayOutput() ZIATrafficForwardingVPNCredentialsArrayOutput {
	return o
}

func (o ZIATrafficForwardingVPNCredentialsArrayOutput) ToZIATrafficForwardingVPNCredentialsArrayOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsArrayOutput {
	return o
}

func (o ZIATrafficForwardingVPNCredentialsArrayOutput) Index(i pulumi.IntInput) ZIATrafficForwardingVPNCredentialsOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ZIATrafficForwardingVPNCredentials {
		return vs[0].([]*ZIATrafficForwardingVPNCredentials)[vs[1].(int)]
	}).(ZIATrafficForwardingVPNCredentialsOutput)
}

type ZIATrafficForwardingVPNCredentialsMapOutput struct{ *pulumi.OutputState }

func (ZIATrafficForwardingVPNCredentialsMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ZIATrafficForwardingVPNCredentials)(nil)).Elem()
}

func (o ZIATrafficForwardingVPNCredentialsMapOutput) ToZIATrafficForwardingVPNCredentialsMapOutput() ZIATrafficForwardingVPNCredentialsMapOutput {
	return o
}

func (o ZIATrafficForwardingVPNCredentialsMapOutput) ToZIATrafficForwardingVPNCredentialsMapOutputWithContext(ctx context.Context) ZIATrafficForwardingVPNCredentialsMapOutput {
	return o
}

func (o ZIATrafficForwardingVPNCredentialsMapOutput) MapIndex(k pulumi.StringInput) ZIATrafficForwardingVPNCredentialsOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ZIATrafficForwardingVPNCredentials {
		return vs[0].(map[string]*ZIATrafficForwardingVPNCredentials)[vs[1].(string)]
	}).(ZIATrafficForwardingVPNCredentialsOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ZIATrafficForwardingVPNCredentialsInput)(nil)).Elem(), &ZIATrafficForwardingVPNCredentials{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIATrafficForwardingVPNCredentialsArrayInput)(nil)).Elem(), ZIATrafficForwardingVPNCredentialsArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ZIATrafficForwardingVPNCredentialsMapInput)(nil)).Elem(), ZIATrafficForwardingVPNCredentialsMap{})
	pulumi.RegisterOutputType(ZIATrafficForwardingVPNCredentialsOutput{})
	pulumi.RegisterOutputType(ZIATrafficForwardingVPNCredentialsArrayOutput{})
	pulumi.RegisterOutputType(ZIATrafficForwardingVPNCredentialsMapOutput{})
}
