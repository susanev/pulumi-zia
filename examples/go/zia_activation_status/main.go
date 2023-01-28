package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/zscaler/pulumi-zia/sdk/go/zia"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := zia.LookupZIAActivationStatus(ctx, nil, nil)
		if err != nil {
			return err
		}
		_, err = zia.NewZIAActivationStatus(ctx, "activationIndex/zIAActivationStatusZIAActivationStatus", &zia.ZIAActivationStatusArgs{
			Status: pulumi.String("ACTIVE"),
		})
		if err != nil {
			return err
		}
		return nil
	})
}
