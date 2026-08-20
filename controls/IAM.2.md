# IAM.2：IAM user 不得直接掛 policy(CIS 1.14，Low)`cis_iam.rego`

- **AWS 判定**:「The control fails if your IAM users have policies attached. Instead, IAM users must inherit permissions from IAM groups or assume a role.」
- **我們的實作**:每個 `aws_iam_user`，若存在指向它的 `aws_iam_user_policy_attachment`(managed)或 `aws_iam_user_policy`(inline)→ deny。兩種掛法都算，對應原文不限 managed/inline。
