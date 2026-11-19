# Groups and named locations that the Conditional Access policies target.

resource "azuread_group" "remote_access_users" {
  display_name     = "${var.prefix}-remote-access-users"
  description      = "Workforce users allowed to use remote access to corporate apps."
  security_enabled = true
}

resource "azuread_group" "privileged_admins" {
  display_name     = "${var.prefix}-privileged-admins"
  description      = "Eligible (not active) admins. Membership grants PIM eligibility only."
  security_enabled = true
}

resource "azuread_named_location" "corporate_egress" {
  count        = length(var.trusted_ip_ranges) > 0 ? 1 : 0
  display_name = "${var.prefix}-corporate-egress"

  ip {
    ip_ranges = var.trusted_ip_ranges
    trusted   = true
  }
}

resource "azuread_named_location" "allowed_countries" {
  display_name = "${var.prefix}-allowed-countries"

  country {
    countries_and_regions                 = var.allowed_countries
    include_unknown_countries_and_regions = false
  }
}
