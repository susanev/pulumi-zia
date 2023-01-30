// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.TimeWindow
{
    public static class GetTimeWindow
    {
        /// <summary>
        /// Use the **zia_firewall_filtering_time_window** data source to get information about a time window option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var workHours = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Work hours",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var weekends = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Weekends",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var offHours = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Off hours",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetTimeWindowResult> InvokeAsync(GetTimeWindowArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTimeWindowResult>("zia:TimeWindow/getTimeWindow:getTimeWindow", args ?? new GetTimeWindowArgs(), options.WithDefaults());

        /// <summary>
        /// Use the **zia_firewall_filtering_time_window** data source to get information about a time window option available in the Zscaler Internet Access cloud firewall. This data source can then be associated with a ZIA firewall filtering rule.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var workHours = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Work hours",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var weekends = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Weekends",
        ///     });
        /// 
        /// });
        /// ```
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Zia = Pulumi.Zia;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var offHours = Zia.TimeWindow.GetTimeWindow.Invoke(new()
        ///     {
        ///         Name = "Off hours",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetTimeWindowResult> Invoke(GetTimeWindowInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTimeWindowResult>("zia:TimeWindow/getTimeWindow:getTimeWindow", args ?? new GetTimeWindowInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTimeWindowArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the time window to be exported.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetTimeWindowArgs()
        {
        }
        public static new GetTimeWindowArgs Empty => new GetTimeWindowArgs();
    }

    public sealed class GetTimeWindowInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the time window to be exported.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public GetTimeWindowInvokeArgs()
        {
        }
        public static new GetTimeWindowInvokeArgs Empty => new GetTimeWindowInvokeArgs();
    }


    [OutputType]
    public sealed class GetTimeWindowResult
    {
        /// <summary>
        /// (String). The supported values are:
        /// </summary>
        public readonly ImmutableArray<string> DayOfWeeks;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly int EndTime;
        public readonly int Id;
        public readonly string? Name;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly int StartTime;

        [OutputConstructor]
        private GetTimeWindowResult(
            ImmutableArray<string> dayOfWeeks,

            int endTime,

            int id,

            string? name,

            int startTime)
        {
            DayOfWeeks = dayOfWeeks;
            EndTime = endTime;
            Id = id;
            Name = name;
            StartTime = startTime;
        }
    }
}