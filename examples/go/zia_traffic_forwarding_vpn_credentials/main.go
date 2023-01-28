package main

import (
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/zscaler/pulumi-zia/sdk/go/zia"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		vpnCredentials, err := zia.NewZIATrafficForwardingVPNCredentials(ctx, "example-vpn-credentials", &zia.ZIATrafficForwardingVPNCredentialsArgs{
			Comments:     pulumi.String("Pulumi Traffic Forwarding VPN Credentials"),
			Fqdn:         pulumi.String("sjc-1-37@securitygeek.io"),
			PreSharedKey: pulumi.String("newPassword123!"),
			Type:         pulumi.String("UFQDN"),
		})
		if err != nil {
			return fmt.Errorf("error creating vpn credential: %v", err)
		}

		ctx.Export("vpncredential", vpnCredentials.Fqdn)

		return nil
	})
}
