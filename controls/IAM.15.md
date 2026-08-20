# IAM.15：密碼政策最小長度 ≥ 14(CIS 1.7，Medium)

- **AWS 判定**:「Use IAM password policies to ensure that passwords are at least…14 characters.」(rule `iam-password-policy`)
- **我們的實作**:`aws_iam_account_password_policy.minimum_password_length >= 14`，**帳號完全沒設密碼政策也是 deny**(Config rule 對無政策帳號回 NON_COMPLIANT)。
