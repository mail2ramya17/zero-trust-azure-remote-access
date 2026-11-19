# Rollout plan

Conditional Access mistakes lock people out, so the baseline is rolled out in stages.

## 1. Prepare
- Create two cloud-only emergency access accounts with FIDO2 keys. Store credentials offline in separate locations.
- Confirm Intune compliance policies exist for every platform remote users use.
- Turn on MFA number matching for Microsoft Authenticator.

## 2. Deploy in report-only
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in real IDs, never commit
terraform init
terraform plan -out tfplan
terraform apply tfplan
```
`ca_policy_state` defaults to `enabledForReportingButNotEnforced`, so nothing is enforced yet.

## 3. Measure impact (1–2 weeks)
Use the Conditional Access insights workbook, or run in Sentinel:
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| mv-expand Policy = todynamic(ConditionalAccessPolicies)
| where tostring(Policy.result) == "reportOnlyFailure"
| summarize Users = dcount(UserPrincipalName), SignIns = count()
          by PolicyName = tostring(Policy.displayName), ClientAppUsed
| order by SignIns desc
```
Fix the causes (non-compliant devices, legacy mail clients, service accounts) before enforcing.

## 4. Enforce
Set `ca_policy_state = "enabled"` and apply. Then export the live policies and run the audit:
```bash
az rest --method get \
  --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies > policies.json
python scripts/ca_policy_audit.py policies.json --break-glass <id1> --break-glass <id2>
```

## 5. Operate
- Run the audit on a schedule to catch drift and exclusion creep.
- Test break-glass sign-in quarterly and confirm the Sentinel incident fires.
- Review PIM activations and approvals monthly.
