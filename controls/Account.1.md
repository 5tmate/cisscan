# Account.1：帳號必須提供安全聯絡人(CIS 1.2，Medium)`cis_account.rego`

- **AWS 判定**:「The control fails if security contact information is not provided for the account.」(Config rule `security-account-information-provided`)
- **我們的實作**:存在 `alternate_contact_type == "SECURITY"` 的 `aws_account_alternate_contact` → pass，否則 deny。BILLING/OPERATIONS 聯絡人不算(AWS 只看 security contact)。
- **閘門**:`collected_types` 需含 `aws_account_alternate_contact`，否則 n/a。
