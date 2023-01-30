// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetURLFilteringRulesArgs, GetURLFilteringRulesResult, GetURLFilteringRulesOutputArgs } from "./getURLFilteringRules";
export const getURLFilteringRules: typeof import("./getURLFilteringRules").getURLFilteringRules = null as any;
export const getURLFilteringRulesOutput: typeof import("./getURLFilteringRules").getURLFilteringRulesOutput = null as any;
utilities.lazyLoad(exports, ["getURLFilteringRules","getURLFilteringRulesOutput"], () => require("./getURLFilteringRules"));

export { URLFilteringRulesArgs, URLFilteringRulesState } from "./urlfilteringRules";
export type URLFilteringRules = import("./urlfilteringRules").URLFilteringRules;
export const URLFilteringRules: typeof import("./urlfilteringRules").URLFilteringRules = null as any;
utilities.lazyLoad(exports, ["URLFilteringRules"], () => require("./urlfilteringRules"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "zia:URLFiltering/uRLFilteringRules:URLFilteringRules":
                return new URLFilteringRules(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("zia", "URLFiltering/uRLFilteringRules", _module)