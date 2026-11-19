# Conditional Access baseline for Zero Trust remote access.
# Every policy excludes the emergency access accounts and ships in the state
# set by var.ca_policy_state (report-only by default).

locals {
  # Built-in "Phishing-resistant MFA" authentication strength.
  phishing_resistant_strength = "00000000-0000-0000-0000-000000000004"

  # Entra directory role template IDs treated as privileged.
  privileged_role_template_ids = [
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", # Cloud Application Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
  ]
}

# CA001: MFA for every user on every app.
resource "azuread_conditional_access_policy" "ca001_mfa_all_users" {
  display_name = "CA001-Global-RequireMFA-AllUsers"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# CA002: Block legacy authentication protocols, which cannot do MFA.
resource "azuread_conditional_access_policy" "ca002_block_legacy_auth" {
  display_name = "CA002-Global-BlockLegacyAuth"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# CA003: Admins need phishing-resistant MFA (FIDO2, Windows Hello, certificate).
resource "azuread_conditional_access_policy" "ca003_admins_phishing_resistant" {
  display_name = "CA003-Admins-RequirePhishingResistantMFA"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_roles = local.privileged_role_template_ids
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator                          = "OR"
    authentication_strength_policy_id = local.phishing_resistant_strength
  }

  session_controls {
    sign_in_frequency        = 4
    sign_in_frequency_period = "hours"
  }
}

# CA004: Remote access to corporate apps only from compliant or hybrid-joined devices.
resource "azuread_conditional_access_policy" "ca004_compliant_device" {
  display_name = "CA004-RemoteAccess-RequireCompliantDevice"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [azuread_group.remote_access_users.object_id]
      excluded_users  = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["compliantDevice", "domainJoinedDevice"]
  }
}

# CA005: Block sign-ins from outside the allowed countries.
resource "azuread_conditional_access_policy" "ca005_block_disallowed_countries" {
  display_name = "CA005-Global-BlockOutsideAllowedCountries"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }

    locations {
      included_locations = ["All"]
      excluded_locations = concat(
        [azuread_named_location.allowed_countries.id],
        [for loc in azuread_named_location.corporate_egress : loc.id]
      )
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# CA006: Risky sign-ins (Entra ID Protection, P2) must re-prove identity with MFA.
resource "azuread_conditional_access_policy" "ca006_risky_signin_mfa" {
  display_name = "CA006-Global-RiskySignIn-RequireMFA"
  state        = var.ca_policy_state

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = ["medium", "high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    sign_in_frequency_interval = "everyTime"
  }
}

# CA007: High user risk forces a secure password change.
resource "azuread_conditional_access_policy" "ca007_high_user_risk" {
  display_name = "CA007-Global-HighUserRisk-RequirePasswordChange"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_object_ids
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }

  session_controls {
    sign_in_frequency_interval = "everyTime"
  }
}
