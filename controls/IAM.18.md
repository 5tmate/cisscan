# IAM.18：必須有掛 AWSSupportAccess 的 support role(CIS 1.16，Low)

- **AWS 判定**:Config rule `iam-policy-in-use`，參數 `policyARN: arn:…:policy/AWSSupportAccess`、`policyUsageType: ANY`，即該 policy 有被使用。
- **我們的實作**:存在 `policy_arn` 以 `:policy/AWSSupportAccess` 結尾的 `aws_iam_role_policy_attachment` → pass。用 endswith 而非全等，是為了同時涵蓋 aws / aws-cn / aws-us-gov partition 的 ARN 前綴(AWS 參數即以 partition 樣板寫成)。
