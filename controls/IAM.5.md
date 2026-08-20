# IAM.5：有 console 密碼的 user 必須開 MFA(CIS 1.9，Medium)

- **AWS 判定**:「checks whether MFA is enabled for all IAM users that use a console password.」
- **我們的實作**:credential report 非 root 列，`password_enabled == true` 且 `mfa_active != true` → deny。純 API user(無密碼)不判，對應原文限定 console password。
