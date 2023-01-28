// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace zscaler.PulumiPackage.Zia.Outputs
{

    [OutputType]
    public sealed class GetZIAAdminUsersExecMobileAppTokenResult
    {
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string Cloud;
        /// <summary>
        /// (Number)
        /// </summary>
        public readonly int CreateTime;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string DeviceId;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string DeviceName;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Number)
        /// </summary>
        public readonly int OrgId;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string Token;
        /// <summary>
        /// (Number)
        /// </summary>
        public readonly int TokenExpiry;
        /// <summary>
        /// (String)
        /// </summary>
        public readonly string TokenId;

        [OutputConstructor]
        private GetZIAAdminUsersExecMobileAppTokenResult(
            string cloud,

            int createTime,

            string deviceId,

            string deviceName,

            string name,

            int orgId,

            string token,

            int tokenExpiry,

            string tokenId)
        {
            Cloud = cloud;
            CreateTime = createTime;
            DeviceId = deviceId;
            DeviceName = deviceName;
            Name = name;
            OrgId = orgId;
            Token = token;
            TokenExpiry = tokenExpiry;
            TokenId = tokenId;
        }
    }
}
