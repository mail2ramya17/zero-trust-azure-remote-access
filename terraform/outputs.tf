output "conditional_access_policy_ids" {
  description = "IDs of the Conditional Access baseline policies."
  value = {
    ca001 = azuread_conditional_access_policy.ca001_mfa_all_users.id
    ca002 = azuread_conditional_access_policy.ca002_block_legacy_auth.id
    ca003 = azuread_conditional_access_policy.ca003_admins_phishing_resistant.id
    ca004 = azuread_conditional_access_policy.ca004_compliant_device.id
    ca005 = azuread_conditional_access_policy.ca005_block_disallowed_countries.id
    ca006 = azuread_conditional_access_policy.ca006_risky_signin_mfa.id
    ca007 = azuread_conditional_access_policy.ca007_high_user_risk.id
  }
}

output "sentinel_workspace_id" {
  description = "Log Analytics workspace backing Microsoft Sentinel."
  value       = azurerm_log_analytics_workspace.sentinel.id
}
