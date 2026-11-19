# Architecture

## Design principles

The design follows the three Zero Trust principles in NIST SP 800-207 and Microsoft's Zero Trust guidance:

| Principle | How this implementation applies it |
|---|---|
| **Verify explicitly** | Every sign-in is evaluated by Conditional Access using identity, device compliance, location and Entra ID Protection risk signals. |
| **Use least privilege** | No standing admin access. Privileged Azure roles are PIM-eligible only and need MFA, justification, a ticket and approval to activate, for at most 4 hours. |
| **Assume breach** | Sign-in and audit logs stream to Microsoft Sentinel. Analytics rules watch the controls themselves: break-glass use, CA tampering, MFA fatigue, off-hours elevation and legacy-auth leaks. |

## Request flow

1. A remote user signs in to a corporate app through Microsoft Entra ID.
2. Entra ID Protection scores sign-in risk and user risk.
3. Conditional Access evaluates the policy set (CA001–CA007):
   - Legacy protocols are blocked outright (CA002).
   - Sign-ins from outside allowed countries are blocked (CA005).
   - Everyone needs MFA (CA001). Admins need phishing-resistant MFA and re-authenticate every 4 hours (CA003).
   - Remote access users must be on a compliant or hybrid-joined device (CA004).
   - Medium or high sign-in risk forces MFA on every sign-in; high user risk forces a secure password change (CA006, CA007).
4. If the user needs to administer Azure resources, they activate an eligible role in PIM. Activation is time-bound and audited.
5. Sign-in logs, audit logs and risk events land in the Sentinel workspace. Scheduled analytics rules raise incidents.
6. Defender for Cloud monitors the workloads behind remote access (VMs, Key Vault, Storage, ARM) and alerts the SOC mailbox.

## Components

| Component | Terraform file | Notes |
|---|---|---|
| Groups and named locations | `terraform/identity.tf` | Remote-access users, PIM-eligible admins, trusted egress IPs, allowed countries |
| Conditional Access baseline | `terraform/conditional_access.tf` | Seven policies, all excluding two break-glass accounts |
| PIM for Azure RBAC | `terraform/pim.tf` | Eligible Contributor assignment plus activation policy |
| Sentinel and Defender | `terraform/monitoring.tf` | Workspace, Entra diagnostic export, analytics rules, Defender plans |
| Detections | `detections/*.kql` | Loaded into Sentinel scheduled rules by Terraform |
| Policy audit | `scripts/ca_policy_audit.py` | Checks a live Graph export for drift from the baseline |

## Licensing assumptions

- Microsoft Entra ID P2 for Entra ID Protection risk conditions (CA006, CA007) and PIM.
- Microsoft Intune for device compliance (CA004).
- Microsoft Sentinel and Defender for Cloud are billed by ingestion and per protected resource.
