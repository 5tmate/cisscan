# EC2.21：NACL 不得從 0.0.0.0/0 開 22/3389(CIS 5.2，Medium)

- **AWS 判定**:「fails if the network ACL inbound entry allows a source CIDR block of '0.0.0.0/0' or '::/0' for TCP ports 22 or 3389. The control doesn't generate findings for a default network ACL.」
- **我們的實作**:`aws_network_acl` 的 ingress:`action == allow`、來源為 `0.0.0.0/0` 或 `::/0`、協定為 tcp(或 -1 全協定)、port 範圍涵蓋 22 或 3389 → deny。**只判 `_type == aws_network_acl`,`aws_default_network_acl` 一律跳過**，對應原文的 default NACL 豁免。
- **collector 注意**:terraformer 匯出時不區分 default NACL，全部標成 `aws_network_acl`，在 P1(terraformer 輸入)下我們會比 AWS 嚴(連 default NACL 一起判)，P2 collector 應把 default NACL 標成 `aws_default_network_acl` 以完全對齊。
