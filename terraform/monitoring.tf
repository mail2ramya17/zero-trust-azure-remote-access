# Microsoft Sentinel, Defender for Cloud and the scheduled analytics rules
# that watch the Zero Trust controls themselves.

resource "azurerm_resource_group" "security" {
  name     = "${var.prefix}-security-rg"
  location = var.location
}

resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "${var.prefix}-sentinel-law"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel.id
}

# Send Entra sign-in and audit logs to the Sentinel workspace.
resource "azurerm_monitor_aad_diagnostic_setting" "entra_to_sentinel" {
  name                       = "${var.prefix}-entra-to-sentinel"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel.id

  dynamic "enabled_log" {
    for_each = [
      "SignInLogs",
      "NonInteractiveUserSignInLogs",
      "AuditLogs",
      "RiskyUsers",
      "UserRiskEvents",
    ]
    content {
      category = enabled_log.value

      retention_policy {
        enabled = false
      }
    }
  }
}

# Scheduled analytics rules, one per KQL file in ../detections.
locals {
  detections = {
    breakglass_signin = {
      name     = "Emergency access account sign-in"
      file     = "breakglass_signin.kql"
      severity = "High"
      tactics  = ["InitialAccess", "PrivilegeEscalation"]
    }
    ca_policy_tampering = {
      name     = "Conditional Access policy changed or disabled"
      file     = "ca_policy_tampering.kql"
      severity = "High"
      tactics  = ["DefenseEvasion"]
    }
    mfa_fatigue = {
      name     = "Possible MFA fatigue (repeated push denials)"
      file     = "mfa_fatigue.kql"
      severity = "Medium"
      tactics  = ["CredentialAccess"]
    }
    pim_activation_off_hours = {
      name     = "PIM role activation outside business hours"
      file     = "pim_activation_off_hours.kql"
      severity = "Medium"
      tactics  = ["PrivilegeEscalation"]
    }
    legacy_auth_success = {
      name     = "Successful legacy authentication sign-in"
      file     = "legacy_auth_success.kql"
      severity = "Medium"
      tactics  = ["DefenseEvasion", "InitialAccess"]
    }
  }
}

# The break-glass rule needs the emergency account IDs injected into its KQL.
locals {
  detection_queries = {
    for key, rule in local.detections : key => replace(
      file("${path.module}/../detections/${rule.file}"),
      "__BREAK_GLASS_IDS__",
      join(", ", formatlist("\"%s\"", var.break_glass_object_ids))
    )
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "zt" {
  for_each = local.detections

  name                       = "${var.prefix}-${each.key}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = each.value.name
  severity                   = each.value.severity
  tactics                    = each.value.tactics
  query                      = local.detection_queries[each.key]
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
}

# Defender for Cloud plans for the workloads behind remote access.
resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = toset(["VirtualMachines", "KeyVaults", "Arm", "StorageAccounts"])
  tier          = "Standard"
  resource_type = each.value
}

resource "azurerm_security_center_contact" "soc" {
  name                = "default"
  email               = var.security_alert_email
  alert_notifications = true
  alerts_to_admins    = true
}
