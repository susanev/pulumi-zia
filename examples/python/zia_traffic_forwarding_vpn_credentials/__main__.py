"""A Python Pulumi program"""

import zscaler_pulumi_zia as zia

# Pre-Shared-Key is "FAKE" used for testing only.
vpnCredentials = zia.ZIATrafficForwardingVPNCredentials("vpn-credentials-example",
    comments = "Pulumi VPN Credentials",
    type = "UFQDN",
    pre_shared_key = "newPassword123!",
    fqdn = "sjc-100@securitygeek.io",
)
