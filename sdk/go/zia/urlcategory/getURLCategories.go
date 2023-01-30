// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package urlcategory

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Use the **zia_url_categories** data source to get information about all or custom URL categories. By default, the response includes keywords.
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//	"github.com/zscaler/pulumi-zia/sdk/go/zia/URLCategory"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := URLCategory.GetURLCategories(ctx, &urlcategory.GetURLCategoriesArgs{
//				Id: pulumi.StringRef("CUSTOM_08"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupURLCategories(ctx *pulumi.Context, args *LookupURLCategoriesArgs, opts ...pulumi.InvokeOption) (*LookupURLCategoriesResult, error) {
	opts = pkgInvokeDefaultOpts(opts)
	var rv LookupURLCategoriesResult
	err := ctx.Invoke("zia:URLCategory/getURLCategories:getURLCategories", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getURLCategories.
type LookupURLCategoriesArgs struct {
	// (String) Name of the URL category. This is only required for custom URL categories.
	ConfiguredName *string `pulumi:"configuredName"`
	// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
	CustomCategory *bool `pulumi:"customCategory"`
	// (Number) The number of custom IP address ranges associated to the URL category.
	CustomIpRangesCount *int `pulumi:"customIpRangesCount"`
	// URL category
	Id *string `pulumi:"id"`
	// (String)
	SuperCategory *string `pulumi:"superCategory"`
}

// A collection of values returned by getURLCategories.
type LookupURLCategoriesResult struct {
	// (String) Name of the URL category. This is only required for custom URL categories.
	ConfiguredName string `pulumi:"configuredName"`
	// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
	CustomCategory bool `pulumi:"customCategory"`
	// (Number) The number of custom IP address ranges associated to the URL category.
	CustomIpRangesCount *int `pulumi:"customIpRangesCount"`
	// (Number) The number of custom URLs associated to the URL category.
	CustomUrlsCount int `pulumi:"customUrlsCount"`
	// (List of String) URLs added to a custom URL category are also retained under the original parent URL category (i.e., the predefined category the URL previously belonged to).
	DbCategorizedUrls []string `pulumi:"dbCategorizedUrls"`
	// (String) Description of the category.
	Description string `pulumi:"description"`
	// (Boolean) Value is set to false for custom URL category when due to scope user does not have edit permission
	Editable bool `pulumi:"editable"`
	// (String) Identifier that uniquely identifies an entity
	Id                                string   `pulumi:"id"`
	IpRanges                          []string `pulumi:"ipRanges"`
	IpRangesRetainingParentCategories []string `pulumi:"ipRangesRetainingParentCategories"`
	// (Number) The number of custom IP address ranges associated to the URL category, that also need to be retained under the original parent category.
	IpRangesRetainingParentCategoryCount int `pulumi:"ipRangesRetainingParentCategoryCount"`
	// (List of String) Custom keywords associated to a URL category. Up to 2048 custom keywords can be added per organization across all categories (including bandwidth classes).
	Keywords                          []string `pulumi:"keywords"`
	KeywordsRetainingParentCategories []string `pulumi:"keywordsRetainingParentCategories"`
	// (List of Object) Scope of the custom categories.
	Scopes []GetURLCategoriesScope `pulumi:"scopes"`
	// (String)
	SuperCategory *string `pulumi:"superCategory"`
	// (String) The admin scope type. The attribute name is subject to change. `ORGANIZATION`, `DEPARTMENT`, `LOCATION`, `LOCATION_GROUP`
	Type string `pulumi:"type"`
	// (List of Object) URL and keyword counts for the category.
	UrlKeywordCounts []GetURLCategoriesUrlKeywordCount `pulumi:"urlKeywordCounts"`
	// (List of String) Custom URLs to add to a URL category. Up to 25,000 custom URLs can be added per organization across all categories (including bandwidth classes).
	Urls []string `pulumi:"urls"`
	// (Number) The number of custom URLs associated to the URL category, that also need to be retained under the original parent category.
	UrlsRetainingParentCategoryCount int `pulumi:"urlsRetainingParentCategoryCount"`
	// (Number)
	Val int `pulumi:"val"`
}

func LookupURLCategoriesOutput(ctx *pulumi.Context, args LookupURLCategoriesOutputArgs, opts ...pulumi.InvokeOption) LookupURLCategoriesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupURLCategoriesResult, error) {
			args := v.(LookupURLCategoriesArgs)
			r, err := LookupURLCategories(ctx, &args, opts...)
			var s LookupURLCategoriesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupURLCategoriesResultOutput)
}

// A collection of arguments for invoking getURLCategories.
type LookupURLCategoriesOutputArgs struct {
	// (String) Name of the URL category. This is only required for custom URL categories.
	ConfiguredName pulumi.StringPtrInput `pulumi:"configuredName"`
	// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
	CustomCategory pulumi.BoolPtrInput `pulumi:"customCategory"`
	// (Number) The number of custom IP address ranges associated to the URL category.
	CustomIpRangesCount pulumi.IntPtrInput `pulumi:"customIpRangesCount"`
	// URL category
	Id pulumi.StringPtrInput `pulumi:"id"`
	// (String)
	SuperCategory pulumi.StringPtrInput `pulumi:"superCategory"`
}

func (LookupURLCategoriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupURLCategoriesArgs)(nil)).Elem()
}

// A collection of values returned by getURLCategories.
type LookupURLCategoriesResultOutput struct{ *pulumi.OutputState }

func (LookupURLCategoriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupURLCategoriesResult)(nil)).Elem()
}

func (o LookupURLCategoriesResultOutput) ToLookupURLCategoriesResultOutput() LookupURLCategoriesResultOutput {
	return o
}

func (o LookupURLCategoriesResultOutput) ToLookupURLCategoriesResultOutputWithContext(ctx context.Context) LookupURLCategoriesResultOutput {
	return o
}

// (String) Name of the URL category. This is only required for custom URL categories.
func (o LookupURLCategoriesResultOutput) ConfiguredName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) string { return v.ConfiguredName }).(pulumi.StringOutput)
}

// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
func (o LookupURLCategoriesResultOutput) CustomCategory() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) bool { return v.CustomCategory }).(pulumi.BoolOutput)
}

// (Number) The number of custom IP address ranges associated to the URL category.
func (o LookupURLCategoriesResultOutput) CustomIpRangesCount() pulumi.IntPtrOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) *int { return v.CustomIpRangesCount }).(pulumi.IntPtrOutput)
}

// (Number) The number of custom URLs associated to the URL category.
func (o LookupURLCategoriesResultOutput) CustomUrlsCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) int { return v.CustomUrlsCount }).(pulumi.IntOutput)
}

// (List of String) URLs added to a custom URL category are also retained under the original parent URL category (i.e., the predefined category the URL previously belonged to).
func (o LookupURLCategoriesResultOutput) DbCategorizedUrls() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.DbCategorizedUrls }).(pulumi.StringArrayOutput)
}

// (String) Description of the category.
func (o LookupURLCategoriesResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) string { return v.Description }).(pulumi.StringOutput)
}

// (Boolean) Value is set to false for custom URL category when due to scope user does not have edit permission
func (o LookupURLCategoriesResultOutput) Editable() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) bool { return v.Editable }).(pulumi.BoolOutput)
}

// (String) Identifier that uniquely identifies an entity
func (o LookupURLCategoriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupURLCategoriesResultOutput) IpRanges() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.IpRanges }).(pulumi.StringArrayOutput)
}

func (o LookupURLCategoriesResultOutput) IpRangesRetainingParentCategories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.IpRangesRetainingParentCategories }).(pulumi.StringArrayOutput)
}

// (Number) The number of custom IP address ranges associated to the URL category, that also need to be retained under the original parent category.
func (o LookupURLCategoriesResultOutput) IpRangesRetainingParentCategoryCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) int { return v.IpRangesRetainingParentCategoryCount }).(pulumi.IntOutput)
}

// (List of String) Custom keywords associated to a URL category. Up to 2048 custom keywords can be added per organization across all categories (including bandwidth classes).
func (o LookupURLCategoriesResultOutput) Keywords() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.Keywords }).(pulumi.StringArrayOutput)
}

func (o LookupURLCategoriesResultOutput) KeywordsRetainingParentCategories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.KeywordsRetainingParentCategories }).(pulumi.StringArrayOutput)
}

// (List of Object) Scope of the custom categories.
func (o LookupURLCategoriesResultOutput) Scopes() GetURLCategoriesScopeArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []GetURLCategoriesScope { return v.Scopes }).(GetURLCategoriesScopeArrayOutput)
}

// (String)
func (o LookupURLCategoriesResultOutput) SuperCategory() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) *string { return v.SuperCategory }).(pulumi.StringPtrOutput)
}

// (String) The admin scope type. The attribute name is subject to change. `ORGANIZATION`, `DEPARTMENT`, `LOCATION`, `LOCATION_GROUP`
func (o LookupURLCategoriesResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) string { return v.Type }).(pulumi.StringOutput)
}

// (List of Object) URL and keyword counts for the category.
func (o LookupURLCategoriesResultOutput) UrlKeywordCounts() GetURLCategoriesUrlKeywordCountArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []GetURLCategoriesUrlKeywordCount { return v.UrlKeywordCounts }).(GetURLCategoriesUrlKeywordCountArrayOutput)
}

// (List of String) Custom URLs to add to a URL category. Up to 25,000 custom URLs can be added per organization across all categories (including bandwidth classes).
func (o LookupURLCategoriesResultOutput) Urls() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) []string { return v.Urls }).(pulumi.StringArrayOutput)
}

// (Number) The number of custom URLs associated to the URL category, that also need to be retained under the original parent category.
func (o LookupURLCategoriesResultOutput) UrlsRetainingParentCategoryCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) int { return v.UrlsRetainingParentCategoryCount }).(pulumi.IntOutput)
}

// (Number)
func (o LookupURLCategoriesResultOutput) Val() pulumi.IntOutput {
	return o.ApplyT(func(v LookupURLCategoriesResult) int { return v.Val }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupURLCategoriesResultOutput{})
}
