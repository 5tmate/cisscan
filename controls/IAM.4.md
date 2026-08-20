# IAM.4：root 不得有 access key(CIS 1.3，Critical)

- **AWS 判定**:「checks whether the root user access key is present.」
- **我們的實作**:credential report 的 `<root_account>` 列，任一 `access_key_{1,2}_active == true` → deny。
