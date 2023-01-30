// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetSecuritySettingsResult } from "./getSecuritySettings";
export const getSecuritySettings: typeof import("./getSecuritySettings").getSecuritySettings = null as any;
utilities.lazyLoad(exports, ["getSecuritySettings"], () => require("./getSecuritySettings"));

export { SecuritySettingsArgs, SecuritySettingsState } from "./securitySettings";
export type SecuritySettings = import("./securitySettings").SecuritySettings;
export const SecuritySettings: typeof import("./securitySettings").SecuritySettings = null as any;
utilities.lazyLoad(exports, ["SecuritySettings"], () => require("./securitySettings"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "zia:SecuritySettings/securitySettings:SecuritySettings":
                return new SecuritySettings(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("zia", "SecuritySettings/securitySettings", _module)