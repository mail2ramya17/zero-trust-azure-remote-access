variable "tenant_id" {
  description = "Microsoft Entra tenant ID."
  type        = string
}

variable "subscription_id" {
  description = "Azure subscription that hosts Sentinel, Defender for Cloud and the PIM-scoped resources."
  type        = string
}

variable "location" {
  description = "Azure region for the security resource group."
  type        = string
  default     = "southcentralus"
}

variable "prefix" {
  description = "Short prefix applied to resource names."
  type        = string
  default     = "zt"
}

variable "ca_policy_state" {
  description = "State for every Conditional Access policy. Start in report-only (enabledForReportingButNotEnforced), review sign-in impact, then promote to enabled. See docs/rollout.md."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.ca_policy_state)
    error_message = "ca_policy_state must be enabled, disabled or enabledForReportingButNotEnforced."
  }
}

variable "break_glass_object_ids" {
  description = "Object IDs of the two cloud-only emergency access accounts. They are excluded from every CA policy and monitored by Sentinel."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_object_ids) >= 2
    error_message = "Provide at least two emergency access accounts."
  }
}

variable "trusted_ip_ranges" {
  description = "Corporate egress CIDR ranges marked as a trusted named location."
  type        = list(string)
  default     = []
}

variable "allowed_countries" {
  description = "ISO 3166-1 alpha-2 country codes from which sign-ins are permitted."
  type        = list(string)
  default     = ["US"]
}

variable "pim_approver_group_object_id" {
  description = "Object ID of the group whose members approve PIM activations for privileged Azure roles."
  type        = string
}

variable "pim_max_activation_hours" {
  description = "Maximum duration of a PIM role activation."
  type        = number
  default     = 4
}

variable "security_alert_email" {
  description = "Mailbox that receives Defender for Cloud alerts."
  type        = string
}
