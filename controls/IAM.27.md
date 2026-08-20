# IAM.27：不得掛 AWSCloudShellFullAccess(CIS 1.21，Medium)

- **AWS 判定**:「checks whether an IAM identity (user, role, or group) has the AWS managed policy AWSCloudShellFullAccess attached.」
- **我們的實作**:三種 attachment 型別(user/group/role)任何一筆的 `policy_arn` 以 `:policy/AWSCloudShellFullAccess` 結尾 → deny，訊息指名身分。endswith 理由同 IAM.18(多 partition)。
