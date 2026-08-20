# IAM.6：root 必須用硬體 MFA(CIS 1.5，Critical)

- **AWS 判定**:「The control fails if hardware MFA isn't enabled or virtual MFA devices are permitted for signing in.」PASS 例外:「Root user credentials aren't present in the account.」
- **我們的實作**:兩段 deny，root 列 `mfa_active != true`(連 MFA 都沒有)，或 `mfa_active == true` 但存在綁定 root 的 `aws_iam_virtual_mfa_device`(`user_arn` 以 `:root` 結尾，或 serial 含 `root-account-mfa-device`)→ MFA 是虛擬的，不算硬體。
- **已知限制**:Organizations 集中管理 root(root 憑證已移除)的帳號，credential report 無法呈現「root 憑證不存在」，此情況會誤報 FAIL。待 collector 增補該事實後修正。
