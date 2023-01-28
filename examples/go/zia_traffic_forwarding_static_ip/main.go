package main

import (
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/zscaler/pulumi-zia/sdk/go/zia"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		staticIP, err := zia.NewZIATrafficForwardingStaticIP(ctx, "static-ip-example", &zia.ZIATrafficForwardingStaticIPArgs{
			Comment:     pulumi.String("Pulumi Traffic Forwarding Static IP"),
			RoutableIp:  pulumi.Bool(true),
			GeoOverride: pulumi.Bool(true),
			IpAddress:   pulumi.String("123.234.244.245"),
			Latitude:    pulumi.Float64Ptr(37.3382082),
			Longitude:   pulumi.Float64Ptr(-121.8863286),
		})
		if err != nil {
			return fmt.Errorf("error creating zia static ip: %v", err)
		}

		ctx.Export("staticIP", staticIP.IpAddress)

		return nil
	})
}
