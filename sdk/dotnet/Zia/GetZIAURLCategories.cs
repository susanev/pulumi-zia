// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia
{
    public static class GetZIAURLCategories
    {
        /// <summary>
        /// Use the **zia_url_categories** data source to get information about all or custom URL categories. By default, the response includes keywords.
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIAURLCategories.Invoke(new()
        ///     {
        ///         Id = "CUSTOM_08",
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetZIAURLCategoriesResult> InvokeAsync(GetZIAURLCategoriesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetZIAURLCategoriesResult>("zia:index/getZIAURLCategories:getZIAURLCategories", args ?? new GetZIAURLCategoriesArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_url_categories** data source to get information about all or custom URL categories. By default, the response includes keywords.
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var example = Zia.GetZIAURLCategories.Invoke(new()
        ///     {
        ///         Id = "CUSTOM_08",
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetZIAURLCategoriesResult> Invoke(GetZIAURLCategoriesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetZIAURLCategoriesResult>("zia:index/getZIAURLCategories:getZIAURLCategories", args ?? new GetZIAURLCategoriesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZIAURLCategoriesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Name of the URL category. This is only required for custom URL categories.
        /// </summary>
        [Input("configuredName")]
        public string? ConfiguredName { get; set; }

        /// <summary>
        /// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
        /// </summary>
        [Input("customCategory")]
        public bool? CustomCategory { get; set; }

        /// <summary>
        /// (Number) The number of custom IP address ranges associated to the URL category.
        /// </summary>
        [Input("customIpRangesCount")]
        public int? CustomIpRangesCount { get; set; }

        /// <summary>
        /// URL category
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// (String)
        /// </summary>
        [Input("superCategory")]
        public string? SuperCategory { get; set; }

        public GetZIAURLCategoriesArgs()
        {
        }
        public static new GetZIAURLCategoriesArgs Empty => new GetZIAURLCategoriesArgs();
    }

    public sealed class GetZIAURLCategoriesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (String) Name of the URL category. This is only required for custom URL categories.
        /// </summary>
        [Input("configuredName")]
        public Input<string>? ConfiguredName { get; set; }

        /// <summary>
        /// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
        /// </summary>
        [Input("customCategory")]
        public Input<bool>? CustomCategory { get; set; }

        /// <summary>
        /// (Number) The number of custom IP address ranges associated to the URL category.
        /// </summary>
        [Input("customIpRangesCount")]
        public Input<int>? CustomIpRangesCount { get; set; }

        /// <summary>
        /// URL category
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// (String)
        /// </summary>
        [Input("superCategory")]
        public Input<string>? SuperCategory { get; set; }

        public GetZIAURLCategoriesInvokeArgs()
        {
        }
        public static new GetZIAURLCategoriesInvokeArgs Empty => new GetZIAURLCategoriesInvokeArgs();
    }


    [OutputType]
    public sealed class GetZIAURLCategoriesResult
    {
        /// <summary>
        /// (String) Name of the URL category. This is only required for custom URL categories.
        /// </summary>
        public readonly string ConfiguredName;
        /// <summary>
        /// (Boolean) Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
        /// </summary>
        public readonly bool CustomCategory;
        /// <summary>
        /// (Number) The number of custom IP address ranges associated to the URL category.
        /// </summary>
        public readonly int? CustomIpRangesCount;
        /// <summary>
        /// (Number) The number of custom URLs associated to the URL category.
        /// </summary>
        public readonly int CustomUrlsCount;
        /// <summary>
        /// (List of String) URLs added to a custom URL category are also retained under the original parent URL category (i.e., the predefined category the URL previously belonged to).
        /// </summary>
        public readonly ImmutableArray<string> DbCategorizedUrls;
        /// <summary>
        /// (String) Description of the category.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// (Boolean) Value is set to false for custom URL category when due to scope user does not have edit permission
        /// </summary>
        public readonly bool Editable;
        /// <summary>
        /// (String) Identifier that uniquely identifies an entity
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<string> IpRanges;
        public readonly ImmutableArray<string> IpRangesRetainingParentCategories;
        /// <summary>
        /// (Number) The number of custom IP address ranges associated to the URL category, that also need to be retained under the original parent category.
        /// </summary>
        public readonly int IpRangesRetainingParentCategoryCount;
        /// <summary>
        /// (List of String) Custom keywords associated to a URL category. Up to 2048 custom keywords can be added per organization across all categories (including bandwidth classes).
        /// </summary>
        public readonly ImmutableArray<string> Keywords;
        public readonly ImmutableArray<string> KeywordsRetainingParentCategories;
        /// <summary>
        /// (List of Object) Scope of the custom categories.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAURLCategoriesScopeResult> Scopes;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string? SuperCategory;
        /// <summary>
        /// (String) The admin scope type. The attribute name is subject to change. `ORGANIZATION`, `DEPARTMENT`, `LOCATION`, `LOCATION_GROUP`
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (List of Object) URL and keyword counts for the category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZIAURLCategoriesUrlKeywordCountResult> UrlKeywordCounts;
        /// <summary>
        /// (List of String) Custom URLs to add to a URL category. Up to 25,000 custom URLs can be added per organization across all categories (including bandwidth classes).
        /// </summary>
        public readonly ImmutableArray<string> Urls;
        /// <summary>
        /// (Number) The number of custom URLs associated to the URL category, that also need to be retained under the original parent category.
        /// </summary>
        public readonly int UrlsRetainingParentCategoryCount;
        /// <summary>
        /// (Number)
        /// </summary>
        public readonly int Val;

        [OutputConstructor]
        private GetZIAURLCategoriesResult(
            string configuredName,

            bool customCategory,

            int? customIpRangesCount,

            int customUrlsCount,

            ImmutableArray<string> dbCategorizedUrls,

            string description,

            bool editable,

            string id,

            ImmutableArray<string> ipRanges,

            ImmutableArray<string> ipRangesRetainingParentCategories,

            int ipRangesRetainingParentCategoryCount,

            ImmutableArray<string> keywords,

            ImmutableArray<string> keywordsRetainingParentCategories,

            ImmutableArray<Outputs.GetZIAURLCategoriesScopeResult> scopes,

            string? superCategory,

            string type,

            ImmutableArray<Outputs.GetZIAURLCategoriesUrlKeywordCountResult> urlKeywordCounts,

            ImmutableArray<string> urls,

            int urlsRetainingParentCategoryCount,

            int val)
        {
            ConfiguredName = configuredName;
            CustomCategory = customCategory;
            CustomIpRangesCount = customIpRangesCount;
            CustomUrlsCount = customUrlsCount;
            DbCategorizedUrls = dbCategorizedUrls;
            Description = description;
            Editable = editable;
            Id = id;
            IpRanges = ipRanges;
            IpRangesRetainingParentCategories = ipRangesRetainingParentCategories;
            IpRangesRetainingParentCategoryCount = ipRangesRetainingParentCategoryCount;
            Keywords = keywords;
            KeywordsRetainingParentCategories = keywordsRetainingParentCategories;
            Scopes = scopes;
            SuperCategory = superCategory;
            Type = type;
            UrlKeywordCounts = urlKeywordCounts;
            Urls = urls;
            UrlsRetainingParentCategoryCount = urlsRetainingParentCategoryCount;
            Val = val;
        }
    }
}
