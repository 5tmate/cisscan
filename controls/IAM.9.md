# IAM.9：root 必須開 MFA(CIS 1.4，Critical)

- **AWS 判定**:「The control fails if MFA isn't enabled for the root user.」
- **我們的實作**:root 列 `mfa_active != true` → deny。與 IAM.6 的差別:這條不管硬體或虛擬。同樣有上述 root-憑證不存在的限制。
