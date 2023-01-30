// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zia

import (
	"fmt"
	"path/filepath"

	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge"
	shim "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim"
	shimv2 "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim/sdk-v2"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/zscaler/pulumi-zia/provider/pkg/version"
	"github.com/zscaler/terraform-provider-zia/v2/zia"
)

// all of the token components used below.
const (
	// This variable controls the default name of the package in the package
	// registries for nodejs and python:
	ziaPkg = "zia"
	// modules:
	adminUsersMod         = "AdminUsers"
	adminRolesMod         = "AdminRoles"
	userMgmtMod           = "Users"
	groupMgmtMod          = "Groups"
	departmentMgmtMod     = "Departments"
	dataLossPreventionMod = "DLP"
	firewallFilteringMod  = "Firewall"
	trafficForwardingMod  = "TrafficForwarding"
	locationManagementMod = "LocationManagement"
	locationGroupsMod     = "LocationGroups"
	urlFilteringMod       = "URLFiltering"
	urlCategoryMod        = "URLCategory"
	ruleLabelsMod         = "RuleLabels"
	authSettingsUrlMod    = "AuthSettingsUrls"
	securitySettingsMod   = "SecuritySettings"
	deviceMod             = "Devices"
	deviceGroupsMod       = "DeviceGroups"
	timeWindowMod         = "TimeWindow"
	activationMod         = "Activation"
	ziaMod                = "index" // the zia module
)

func preConfigureCallback(vars resource.PropertyMap, c shim.ResourceConfig) error {
	return nil
}

func refProviderLicense(license tfbridge.TFProviderLicense) *tfbridge.TFProviderLicense {
	return &license
}

// Provider returns additional overlaid schema and metadata associated with the provider..
func Provider() tfbridge.ProviderInfo {
	// Instantiate the Terraform provider
	p := shimv2.NewProvider(zia.Provider())

	// Create a Pulumi provider mapping
	prov := tfbridge.ProviderInfo{
		P:                       p,
		Name:                    "zia",
		Description:             "A Pulumi package for creating and managing zia cloud resources.",
		Keywords:                []string{"pulumi", "zia", "zscaler", "category/cloud"},
		TFProviderLicense:       refProviderLicense(tfbridge.MITLicenseType),
		License:                 "MIT",
		Homepage:                "https://www.zscaler.com",
		Repository:              "https://github.com/zscaler/pulumi-zia",
		PluginDownloadURL:       "github://api.github.com/zscaler",
		LogoURL:                 "https://www.zscaler.com/themes/custom/zscaler/logo.svg", //nolint:golint,lll
		GitHubOrg:               "zscaler",
		Publisher:               "Zscaler",
		DisplayName:             "Zscaler Internet Access",
		TFProviderVersion:       "2.3.6",
		TFProviderModuleVersion: "v2",
		Config: map[string]*tfbridge.SchemaInfo{
			"username": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"ZIA_USERNAME"},
				},
			},
			"password": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"ZIA_PASSWORD"},
				},
			},
			"api_key": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"ZIA_API_KEY"},
				},
			},
			"zia_cloud": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"ZIA_CLOUD"},
				},
			},
		},
		PreConfigureCallback: preConfigureCallback,
		Resources: map[string]*tfbridge.ResourceInfo{
			"zia_admin_users": {Tok: tfbridge.MakeResource(ziaPkg, adminUsersMod, "AdminUsers"),
				Docs: &tfbridge.DocInfo{Source: "zia_admin_users.md"},
			},
			"zia_dlp_dictionaries": {Tok: tfbridge.MakeResource(ziaPkg, dataLossPreventionMod, "DLPDictionaries"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_dictionaries.md"},
			},
			"zia_dlp_notification_templates": {Tok: tfbridge.MakeResource(ziaPkg, dataLossPreventionMod, "DLPNotificationTemplates"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_notification_templates.md"},
			},
			"zia_dlp_web_rules": {Tok: tfbridge.MakeResource(ziaPkg, dataLossPreventionMod, "DLPWebRules"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_web_rules.md"},
			},
			"zia_firewall_filtering_rule": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringRule"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_rule.md"},
			},
			"zia_firewall_filtering_destination_groups": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringDestinationGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_destination_groups.md"},
			},
			"zia_firewall_filtering_ip_source_groups": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringSourceGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_ip_source_groups.md"},
			},
			"zia_firewall_filtering_network_service": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringNetworkServices"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_service.md"},
			},
			"zia_firewall_filtering_network_service_groups": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringServiceGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_service_groups.md"},
			},
			"zia_firewall_filtering_network_application_groups": {Tok: tfbridge.MakeResource(ziaPkg, firewallFilteringMod, "FirewallFilteringApplicationGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_application_groups.md"},
			},
			"zia_traffic_forwarding_gre_tunnel": {Tok: tfbridge.MakeResource(ziaPkg, trafficForwardingMod, "TrafficForwardingGRETunnel"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_gre_tunnel.md"},
			},
			"zia_traffic_forwarding_static_ip": {Tok: tfbridge.MakeResource(ziaPkg, trafficForwardingMod, "TrafficForwardingStaticIP"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_static_ip.md"},
			},
			"zia_traffic_forwarding_vpn_credentials": {Tok: tfbridge.MakeResource(ziaPkg, trafficForwardingMod, "TrafficForwardingVPNCredentials"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_vpn_credentials.md"},
			},
			"zia_location_management": {Tok: tfbridge.MakeResource(ziaPkg, locationManagementMod, "LocationManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_location_management.md"},
			},
			"zia_url_categories": {Tok: tfbridge.MakeResource(ziaPkg, urlCategoryMod, "URLCategories"),
				Docs: &tfbridge.DocInfo{Source: "zia_url_categories.md"},
			},
			"zia_url_filtering_rules": {Tok: tfbridge.MakeResource(ziaPkg, urlFilteringMod, "URLFilteringRules"),
				Docs: &tfbridge.DocInfo{Source: "zia_url_filtering_rules.md"},
			},
			"zia_user_management": {Tok: tfbridge.MakeResource(ziaPkg, userMgmtMod, "UserManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_user_management.md"},
			},
			"zia_rule_labels": {Tok: tfbridge.MakeResource(ziaPkg, ruleLabelsMod, "RuleLabels"),
				Docs: &tfbridge.DocInfo{Source: "zia_rule_labels.md"},
			},
			"zia_auth_settings_urls": {Tok: tfbridge.MakeResource(ziaPkg, authSettingsUrlMod, "AuthSettingsURLs"),
				Docs: &tfbridge.DocInfo{Source: "zia_auth_settings_urls.md"},
			},
			"zia_security_settings": {Tok: tfbridge.MakeResource(ziaPkg, securitySettingsMod, "SecuritySettings"),
				Docs: &tfbridge.DocInfo{Source: "zia_security_settings.md"},
			},
			"zia_activation_status": {Tok: tfbridge.MakeResource(ziaPkg, activationMod, "ActivationStatus"),
				Docs: &tfbridge.DocInfo{Source: "zia_activation_status.md"}},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			"zia_admin_users": {Tok: tfbridge.MakeDataSource(ziaPkg, adminUsersMod, "getAdminUsers"),
				Docs: &tfbridge.DocInfo{Source: "zia_admin_users.md"},
			},
			"zia_admin_roles": {Tok: tfbridge.MakeDataSource(ziaPkg, adminRolesMod, "getAdminRoles"),
				Docs: &tfbridge.DocInfo{Source: "zia_admin_roles.md"},
			},
			"zia_user_management": {Tok: tfbridge.MakeDataSource(ziaPkg, userMgmtMod, "getUserManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_user_management.md"},
			},
			"zia_group_management": {Tok: tfbridge.MakeDataSource(ziaPkg, groupMgmtMod, "getGroupManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_group_management.md"},
			},
			"zia_department_management": {Tok: tfbridge.MakeDataSource(ziaPkg, departmentMgmtMod, "getDepartmentManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_department_management.md"},
			},
			"zia_firewall_filtering_rule": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringRule"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_rule.md"},
			},
			"zia_firewall_filtering_destination_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringDestinationGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_destination_groups.md"},
			},
			"zia_firewall_filtering_ip_source_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringSourceIPGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_ip_source_groups.md"},
			},
			"zia_firewall_filtering_network_service": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringNetworkServices"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_service.md"},
			},
			"zia_firewall_filtering_network_service_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringNetworkServiceGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_service_groups.md"},
			},
			"zia_firewall_filtering_network_application_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringApplicationGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_application_groups.md"},
			},
			"zia_firewall_filtering_network_application": {Tok: tfbridge.MakeDataSource(ziaPkg, firewallFilteringMod, "getFirewallFilteringApplication"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_network_application.md"},
			},
			"zia_traffic_forwarding_gre_tunnel": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingGRETunnel"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_gre_tunnel.md"},
			},
			"zia_traffic_forwarding_public_node_vips": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingNodeVIPs"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_public_node_vips.md"},
			},
			"zia_traffic_forwarding_gre_vip_recommended_list": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingVIPRecommendedList"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_gre_vip_recommended_list.md"},
			},
			"zia_traffic_forwarding_gre_tunnel_info": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingGRETunnelInfo"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_gre_tunnel_info.md"},
			},
			"zia_gre_internal_ip_range_list": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingGREInternalIPRange")},
			"zia_traffic_forwarding_static_ip": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingStaticIP"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_static_ip.md"},
			},
			"zia_traffic_forwarding_vpn_credentials": {Tok: tfbridge.MakeDataSource(ziaPkg, trafficForwardingMod, "getTrafficForwardingVPNCredentials"),
				Docs: &tfbridge.DocInfo{Source: "zia_traffic_forwarding_vpn_credentials.md"},
			},
			"zia_location_management": {Tok: tfbridge.MakeDataSource(ziaPkg, locationManagementMod, "getLocationManagement"),
				Docs: &tfbridge.DocInfo{Source: "zia_location_management.md"},
			},
			"zia_location_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, locationGroupsMod, "getLocationGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_location_groups.md"},
			},
			"zia_url_categories": {Tok: tfbridge.MakeDataSource(ziaPkg, urlCategoryMod, "getURLCategories"),
				Docs: &tfbridge.DocInfo{Source: "zia_url_categories.md"},
			},
			"zia_url_filtering_rules": {Tok: tfbridge.MakeDataSource(ziaPkg, urlFilteringMod, "getURLFilteringRules"),
				Docs: &tfbridge.DocInfo{Source: "zia_url_filtering_rules.md"},
			},
			"zia_dlp_engines": {Tok: tfbridge.MakeDataSource(ziaPkg, dataLossPreventionMod, "getDLPEngines"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_engines.md"},
			},
			"zia_dlp_dictionaries": {Tok: tfbridge.MakeDataSource(ziaPkg, dataLossPreventionMod, "getDLPDictionaries"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_dictionaries.md"},
			},
			"zia_dlp_notification_templates": {Tok: tfbridge.MakeDataSource(ziaPkg, dataLossPreventionMod, "getDLPNotificationTemplates"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_notification_templates.md"},
			},
			"zia_dlp_web_rules": {Tok: tfbridge.MakeDataSource(ziaPkg, dataLossPreventionMod, "getDLPWebRules"),
				Docs: &tfbridge.DocInfo{Source: "zia_dlp_web_rules.md"},
			},
			"zia_rule_labels": {Tok: tfbridge.MakeDataSource(ziaPkg, ruleLabelsMod, "getRuleLabels"),
				Docs: &tfbridge.DocInfo{Source: "zia_rule_labels.md"},
			},
			"zia_device_groups": {Tok: tfbridge.MakeDataSource(ziaPkg, deviceGroupsMod, "getDeviceGroups"),
				Docs: &tfbridge.DocInfo{Source: "zia_device_groups.md"},
			},
			"zia_devices": {Tok: tfbridge.MakeDataSource(ziaPkg, deviceMod, "getDevices"),
				Docs: &tfbridge.DocInfo{Source: "zia_devices.md"},
			},
			"zia_auth_settings_urls": {Tok: tfbridge.MakeDataSource(ziaPkg, authSettingsUrlMod, "getAuthSettingsURLs"),
				Docs: &tfbridge.DocInfo{Source: "zia_auth_settings_urls.md"},
			},
			"zia_security_settings": {Tok: tfbridge.MakeDataSource(ziaPkg, securitySettingsMod, "getSecuritySettings"),
				Docs: &tfbridge.DocInfo{Source: "zia_security_settings.md"},
			},
			"zia_firewall_filtering_time_window": {Tok: tfbridge.MakeDataSource(ziaPkg, timeWindowMod, "getTimeWindow"),
				Docs: &tfbridge.DocInfo{Source: "zia_firewall_filtering_time_window.md"},
			},
			"zia_activation_status": {Tok: tfbridge.MakeDataSource(ziaPkg, activationMod, "getActivationStatus"),
				Docs: &tfbridge.DocInfo{Source: "zia_activation_status.md"},
			},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			// List any npm dependencies and their versions
			Dependencies: map[string]string{
				"@pulumi/pulumi": "^3.0.0",
			},
			DevDependencies: map[string]string{
				"@types/node": "^10.0.0", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			PackageName: "@zscaler/pulumi-zia",
			// See the documentation for tfbridge.OverlayInfo for how to lay out this
			// section, or refer to the AWS provider. Delete this section if there are
			// no overlay files.
			//Overlay: &tfbridge.OverlayInfo{},
		},
		Python: &tfbridge.PythonInfo{
			PackageName: "zscaler_pulumi_zia",
			// List any Python dependencies and their version ranges
			Requires: map[string]string{
				"pulumi": ">=3.0.0,<4.0.0",
			},
		},
		Golang: &tfbridge.GolangInfo{
			ImportBasePath: filepath.Join(
				fmt.Sprintf("github.com/zscaler/pulumi-%[1]s/sdk/", ziaPkg),
				tfbridge.GetModuleMajorVersion(version.Version),
				"go",
				ziaPkg,
			),
			GenerateResourceContainerTypes: true,
		},
		CSharp: &tfbridge.CSharpInfo{
			RootNamespace: "zscaler.PulumiPackage",
			PackageReferences: map[string]string{
				"Pulumi": "3.*",
			},
		},
	}

	prov.SetAutonaming(255, "-")

	return prov
}
