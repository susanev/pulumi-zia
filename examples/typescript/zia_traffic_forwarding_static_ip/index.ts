import * as pulumi from "@pulumi/pulumi";
import * as zia from "@zscaler/zia";

// ZIA Traffic Forwarding - Static IP
const staticIP = new zia.ZIATrafficForwardingStaticIP("static_ip_example", {
    comment: "Pulumi Traffic Forwarding Static IP",
    geoOverride: true,
    ipAddress: "123.234.244.245",
    latitude: -36.848461,
    longitude: 174.763336,
    routableIp: true,
});