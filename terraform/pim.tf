# Privileged Identity Management for Azure RBAC.
# Admins hold no standing access. Members of the privileged-admins group are
# eligible for Contributor on the subscription and must activate it with MFA,
# a justification and approval, for a limited time.

data "azurerm_subscription" "current" {}

# Unscoped lookup returns "/providers/Microsoft.Authorization/roleDefinitions/<guid>",
# which is prefixed with the subscription ID below.
data "azurerm_role_definition" "contributor" {
  name = "Contributor"
}

resource "time_static" "pim_start" {}

resource "azurerm_pim_eligible_role_assignment" "admins_contributor" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = "${data.azurerm_subscription.current.id}${data.azurerm_role_definition.contributor.id}"
  principal_id       = azuread_group.privileged_admins.object_id
  justification      = "Zero Trust baseline: eligible-only access for platform admins."

  schedule {
    start_date_time = time_static.pim_start.rfc3339
    expiration {
      duration_days = 180
    }
  }
}

resource "azurerm_role_management_policy" "contributor_activation" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = "${data.azurerm_subscription.current.id}${data.azurerm_role_definition.contributor.id}"

  activation_rules {
    maximum_duration                   = "PT${var.pim_max_activation_hours}H"
    require_multifactor_authentication = true
    require_justification              = true
    require_ticket_info                = true
    require_approval                   = true

    approval_stage {
      primary_approver {
        object_id = var.pim_approver_group_object_id
        type      = "Group"
      }
    }
  }

  active_assignment_rules {
    expire_after                       = "P15D"
    require_multifactor_authentication = true
    require_justification              = true
  }

  eligible_assignment_rules {
    expiration_required = true
    expire_after        = "P180D"
  }

  notification_rules {
    active_assignments {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
        additional_recipients = [var.security_alert_email]
      }
    }
  }
}
