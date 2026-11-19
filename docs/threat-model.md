# Threat model

Scope: workforce users reaching corporate applications and Azure resources from outside the corporate network.

| # | Threat | Example technique (MITRE ATT&CK) | Preventive control | Detective control |
|---|---|---|---|---|
| T1 | Password spray or credential stuffing | T1110.003, T1110.004 | CA001 MFA for all users, CA005 country block | Entra ID Protection risk → CA006 |
| T2 | Legacy protocol abuse to bypass MFA | T1078 | CA002 block legacy auth | `legacy_auth_success.kql` |
| T3 | MFA fatigue / push bombing | T1621 | Number matching (tenant setting), CA003 phishing-resistant MFA for admins | `mfa_fatigue.kql` |
| T4 | Adversary-in-the-middle token theft against admins | T1557, T1539 | CA003 phishing-resistant MFA, 4-hour sign-in frequency | Entra ID Protection anomalous token detections |
| T5 | Unmanaged or compromised endpoint | T1078 | CA004 compliant device required | Defender for Cloud and Intune compliance reports |
| T6 | Standing privilege abused after account takeover | T1078.004, T1098 | PIM eligible-only, MFA + approval to activate, 4-hour cap | `pim_activation_off_hours.kql` |
| T7 | Attacker weakens or disables Conditional Access | T1562 | CA admin role covered by CA003; PIM for directory roles | `ca_policy_tampering.kql` |
| T8 | Emergency access account misuse | T1078.004 | Long random passwords, FIDO2 keys in a safe, excluded only from CA | `breakglass_signin.kql` |
| T9 | Lockout from a bad policy | — (availability) | Two break-glass accounts excluded from every policy; report-only rollout | `scripts/ca_policy_audit.py` ZT-04 |

## Residual risks

- Break-glass accounts are deliberately outside Conditional Access. Their safety relies on credential custody and the T8 detection.
- Country-based blocking is weak against VPNs and residential proxies; it reduces noise rather than stopping a determined attacker.
- Session token replay on non-admin users is reduced but not eliminated. Token protection policies are a next step.
