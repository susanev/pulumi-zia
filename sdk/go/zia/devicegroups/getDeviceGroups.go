// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devicegroups

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_device_groups** data source to get information about a device group in the Zscaler Internet Access cloud or via the API. This data source can then be associated with resources such as: URL Filtering Rules
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//	"github.com/zscaler/pulumi-zia/sdk/go/zia/DeviceGroups"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DeviceGroups.GetDeviceGroups(ctx, &devicegroups.GetDeviceGroupsArgs{
//				Name: pulumi.StringRef("IOS"),
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
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//	"github.com/zscaler/pulumi-zia/sdk/go/zia/DeviceGroups"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DeviceGroups.GetDeviceGroups(ctx, &devicegroups.GetDeviceGroupsArgs{
//				Name: pulumi.StringRef("Android"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDeviceGroups(ctx *pulumi.Context, args *GetDeviceGroupsArgs, opts ...pulumi.InvokeOption) (*GetDeviceGroupsResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv GetDeviceGroupsResult
	err := ctx.Invoke("zia:DeviceGroups/getDeviceGroups:getDeviceGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeviceGroups.
type GetDeviceGroupsArgs struct {
	// The name of the device group to be exported.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getDeviceGroups.
type GetDeviceGroupsResult struct {
	// (String) The device group's description.
	Description string `pulumi:"description"`
	// (int) The number of devices within the group.
	DeviceCount int `pulumi:"deviceCount"`
	// (String) The names of devices that belong to the device group. The device names are comma-separated.
	DeviceNames string `pulumi:"deviceNames"`
	// (String) The device group type. i.e ``ZCC_OS``, ``NON_ZCC``, ``CBI``
	GroupType string `pulumi:"groupType"`
	// (String) The unique identifer for the device group.
	Id int `pulumi:"id"`
	// (String) The device group name.
	Name *string `pulumi:"name"`
	// (String) The operating system (OS).
	OsType string `pulumi:"osType"`
	// (Boolean) Indicates whether this is a predefined device group. If this value is set to true, the group is predefined.
	Predefined bool `pulumi:"predefined"`
}

func GetDeviceGroupsOutput(ctx *pulumi.Context, args GetDeviceGroupsOutputArgs, opts ...pulumi.InvokeOption) GetDeviceGroupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDeviceGroupsResult, error) {
			args := v.(GetDeviceGroupsArgs)
			r, err := GetDeviceGroups(ctx, &args, opts...)
			var s GetDeviceGroupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDeviceGroupsResultOutput)
}

// A collection of arguments for invoking getDeviceGroups.
type GetDeviceGroupsOutputArgs struct {
	// The name of the device group to be exported.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetDeviceGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeviceGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getDeviceGroups.
type GetDeviceGroupsResultOutput struct{ *pulumi.OutputState }

func (GetDeviceGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeviceGroupsResult)(nil)).Elem()
}

func (o GetDeviceGroupsResultOutput) ToGetDeviceGroupsResultOutput() GetDeviceGroupsResultOutput {
	return o
}

func (o GetDeviceGroupsResultOutput) ToGetDeviceGroupsResultOutputWithContext(ctx context.Context) GetDeviceGroupsResultOutput {
	return o
}

// (String) The device group's description.
func (o GetDeviceGroupsResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) string { return v.Description }).(pulumi.StringOutput)
}

// (int) The number of devices within the group.
func (o GetDeviceGroupsResultOutput) DeviceCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) int { return v.DeviceCount }).(pulumi.IntOutput)
}

// (String) The names of devices that belong to the device group. The device names are comma-separated.
func (o GetDeviceGroupsResultOutput) DeviceNames() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) string { return v.DeviceNames }).(pulumi.StringOutput)
}

// (String) The device group type. i.e “ZCC_OS“, “NON_ZCC“, “CBI“
func (o GetDeviceGroupsResultOutput) GroupType() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) string { return v.GroupType }).(pulumi.StringOutput)
}

// (String) The unique identifer for the device group.
func (o GetDeviceGroupsResultOutput) Id() pulumi.IntOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) int { return v.Id }).(pulumi.IntOutput)
}

// (String) The device group name.
func (o GetDeviceGroupsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// (String) The operating system (OS).
func (o GetDeviceGroupsResultOutput) OsType() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) string { return v.OsType }).(pulumi.StringOutput)
}

// (Boolean) Indicates whether this is a predefined device group. If this value is set to true, the group is predefined.
func (o GetDeviceGroupsResultOutput) Predefined() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDeviceGroupsResult) bool { return v.Predefined }).(pulumi.BoolOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeviceGroupsResultOutput{})
}
