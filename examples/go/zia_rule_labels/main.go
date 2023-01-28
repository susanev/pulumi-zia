package main

import (
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/zscaler/pulumi-zia/sdk/go/zia"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		ruleLabel, err := zia.NewZIARuleLabels(ctx, "example-rule-label", &zia.ZIARuleLabelsArgs{
			Name:        pulumi.String("Pulumi Rule Label"),
			Description: pulumi.String("Pulumi Rule Label"),
		})
		if err != nil {
			return fmt.Errorf("error creating vpn credential: %v", err)
		}

		ctx.Export("label_id", ruleLabel.ID())

		return nil
	})
}
