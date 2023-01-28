// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

/**
 * The **zia_traffic_forwarding_gre_tunnel** resource allows the creation and management of GRE tunnel configuration in the Zscaler Internet Access (ZIA) portal.
 *
 * > **Note:** The provider automatically query the Zscaler cloud for the primary and secondary destination datacenter and virtual IP address (VIP) of the GRE tunnel. The parameter can be overriden if needed by setting the parameters: `primaryDestVip` and `secondaryDestVip`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@zscaler/pulumi-zia";
 *
 * // ZIA Traffic Forwarding - Static IP
 * const exampleZIATrafficForwardingStaticIP = new zia.ZIATrafficForwardingStaticIP("exampleZIATrafficForwardingStaticIP", {
 *     ipAddress: "1.1.1.1",
 *     routableIp: true,
 *     comment: "Example",
 *     geoOverride: true,
 *     latitude: 37.418171,
 *     longitude: -121.95314,
 * });
 * // Creates a numbered GRE Tunnel
 * const exampleZIATrafficForwardingGRETunnel = new zia.ZIATrafficForwardingGRETunnel("exampleZIATrafficForwardingGRETunnel", {
 *     sourceIp: exampleZIATrafficForwardingStaticIP.ipAddress,
 *     comment: "Example",
 *     withinCountry: true,
 *     countryCode: "US",
 *     ipUnnumbered: false,
 * }, {
 *     dependsOn: [exampleZIATrafficForwardingStaticIP],
 * });
 * ```
 *
 * > **Note:** The provider will automatically query and set the Zscaler cloud for the next available `/29` internal IP range to be used in a numbered GRE tunnel.
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as zia from "@zscaler/pulumi-zia";
 *
 * // ZIA Traffic Forwarding - Static IP
 * const example = new zia.ZIATrafficForwardingStaticIP("example", {
 *     ipAddress: "1.1.1.1",
 *     routableIp: true,
 *     comment: "Example",
 *     geoOverride: true,
 *     latitude: 37.418171,
 *     longitude: -121.95314,
 * });
 * // Creates an unnumbered GRE Tunnel
 * const telusHomeInternet01Gre01 = new zia.ZIATrafficForwardingGRETunnel("telusHomeInternet01Gre01", {
 *     sourceIp: example.ipAddress,
 *     comment: "Example",
 *     withinCountry: true,
 *     countryCode: "CA",
 *     ipUnnumbered: true,
 * }, {
 *     dependsOn: [example],
 * });
 * ```
 */
export class ZIATrafficForwardingGRETunnel extends pulumi.CustomResource {
    /**
     * Get an existing ZIATrafficForwardingGRETunnel resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ZIATrafficForwardingGRETunnelState, opts?: pulumi.CustomResourceOptions): ZIATrafficForwardingGRETunnel {
        return new ZIATrafficForwardingGRETunnel(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'zia:index/zIATrafficForwardingGRETunnel:ZIATrafficForwardingGRETunnel';

    /**
     * Returns true if the given object is an instance of ZIATrafficForwardingGRETunnel.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ZIATrafficForwardingGRETunnel {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ZIATrafficForwardingGRETunnel.__pulumiType;
    }

    /**
     * Additional information about this GRE tunnel
     */
    public readonly comment!: pulumi.Output<string | undefined>;
    /**
     * When withinCountry is enabled, you must set this to the country code.
     */
    public readonly countryCode!: pulumi.Output<string>;
    /**
     * The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ipUnnumbered` is set to `false`.
     */
    public readonly internalIpRange!: pulumi.Output<string>;
    /**
     * This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true greTunIp and greTunId are set to null
     */
    public readonly ipUnnumbered!: pulumi.Output<boolean>;
    public /*out*/ readonly lastModificationTime!: pulumi.Output<number>;
    public /*out*/ readonly lastModifiedBies!: pulumi.Output<outputs.ZIATrafficForwardingGRETunnelLastModifiedBy[]>;
    /**
     * **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    public readonly primaryDestVips!: pulumi.Output<outputs.ZIATrafficForwardingGRETunnelPrimaryDestVip[]>;
    /**
     * The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    public readonly secondaryDestVips!: pulumi.Output<outputs.ZIATrafficForwardingGRETunnelSecondaryDestVip[]>;
    /**
     * The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
     */
    public readonly sourceIp!: pulumi.Output<string>;
    /**
     * The ID of the GRE tunnel.
     */
    public /*out*/ readonly tunnelId!: pulumi.Output<number>;
    /**
     * Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
     */
    public readonly withinCountry!: pulumi.Output<boolean>;

    /**
     * Create a ZIATrafficForwardingGRETunnel resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ZIATrafficForwardingGRETunnelArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ZIATrafficForwardingGRETunnelArgs | ZIATrafficForwardingGRETunnelState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ZIATrafficForwardingGRETunnelState | undefined;
            resourceInputs["comment"] = state ? state.comment : undefined;
            resourceInputs["countryCode"] = state ? state.countryCode : undefined;
            resourceInputs["internalIpRange"] = state ? state.internalIpRange : undefined;
            resourceInputs["ipUnnumbered"] = state ? state.ipUnnumbered : undefined;
            resourceInputs["lastModificationTime"] = state ? state.lastModificationTime : undefined;
            resourceInputs["lastModifiedBies"] = state ? state.lastModifiedBies : undefined;
            resourceInputs["primaryDestVips"] = state ? state.primaryDestVips : undefined;
            resourceInputs["secondaryDestVips"] = state ? state.secondaryDestVips : undefined;
            resourceInputs["sourceIp"] = state ? state.sourceIp : undefined;
            resourceInputs["tunnelId"] = state ? state.tunnelId : undefined;
            resourceInputs["withinCountry"] = state ? state.withinCountry : undefined;
        } else {
            const args = argsOrState as ZIATrafficForwardingGRETunnelArgs | undefined;
            if ((!args || args.sourceIp === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceIp'");
            }
            resourceInputs["comment"] = args ? args.comment : undefined;
            resourceInputs["countryCode"] = args ? args.countryCode : undefined;
            resourceInputs["internalIpRange"] = args ? args.internalIpRange : undefined;
            resourceInputs["ipUnnumbered"] = args ? args.ipUnnumbered : undefined;
            resourceInputs["primaryDestVips"] = args ? args.primaryDestVips : undefined;
            resourceInputs["secondaryDestVips"] = args ? args.secondaryDestVips : undefined;
            resourceInputs["sourceIp"] = args ? args.sourceIp : undefined;
            resourceInputs["withinCountry"] = args ? args.withinCountry : undefined;
            resourceInputs["lastModificationTime"] = undefined /*out*/;
            resourceInputs["lastModifiedBies"] = undefined /*out*/;
            resourceInputs["tunnelId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ZIATrafficForwardingGRETunnel.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ZIATrafficForwardingGRETunnel resources.
 */
export interface ZIATrafficForwardingGRETunnelState {
    /**
     * Additional information about this GRE tunnel
     */
    comment?: pulumi.Input<string>;
    /**
     * When withinCountry is enabled, you must set this to the country code.
     */
    countryCode?: pulumi.Input<string>;
    /**
     * The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ipUnnumbered` is set to `false`.
     */
    internalIpRange?: pulumi.Input<string>;
    /**
     * This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true greTunIp and greTunId are set to null
     */
    ipUnnumbered?: pulumi.Input<boolean>;
    lastModificationTime?: pulumi.Input<number>;
    lastModifiedBies?: pulumi.Input<pulumi.Input<inputs.ZIATrafficForwardingGRETunnelLastModifiedBy>[]>;
    /**
     * **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    primaryDestVips?: pulumi.Input<pulumi.Input<inputs.ZIATrafficForwardingGRETunnelPrimaryDestVip>[]>;
    /**
     * The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    secondaryDestVips?: pulumi.Input<pulumi.Input<inputs.ZIATrafficForwardingGRETunnelSecondaryDestVip>[]>;
    /**
     * The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
     */
    sourceIp?: pulumi.Input<string>;
    /**
     * The ID of the GRE tunnel.
     */
    tunnelId?: pulumi.Input<number>;
    /**
     * Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
     */
    withinCountry?: pulumi.Input<boolean>;
}

/**
 * The set of arguments for constructing a ZIATrafficForwardingGRETunnel resource.
 */
export interface ZIATrafficForwardingGRETunnelArgs {
    /**
     * Additional information about this GRE tunnel
     */
    comment?: pulumi.Input<string>;
    /**
     * When withinCountry is enabled, you must set this to the country code.
     */
    countryCode?: pulumi.Input<string>;
    /**
     * The start of the internal IP address in /29 CIDR range. Automatically set by the provider if `ipUnnumbered` is set to `false`.
     */
    internalIpRange?: pulumi.Input<string>;
    /**
     * This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true greTunIp and greTunId are set to null
     */
    ipUnnumbered?: pulumi.Input<boolean>;
    /**
     * **` (Optional) The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    primaryDestVips?: pulumi.Input<pulumi.Input<inputs.ZIATrafficForwardingGRETunnelPrimaryDestVip>[]>;
    /**
     * The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
     */
    secondaryDestVips?: pulumi.Input<pulumi.Input<inputs.ZIATrafficForwardingGRETunnelSecondaryDestVip>[]>;
    /**
     * The source IP address of the GRE tunnel. This is typically a static IP address in the organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
     */
    sourceIp: pulumi.Input<string>;
    /**
     * Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
     */
    withinCountry?: pulumi.Input<boolean>;
}