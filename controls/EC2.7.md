# EC2.7：EBS 帳號級預設加密(CIS 5.1.1，Medium)

- **AWS 判定**:「checks whether account-level encryption is enabled by default for EBS volumes」(resource type `AWS::::Account`，逐 region)。
- **我們的實作**:合成型別 `aws_ebs_encryption_by_default`(collector 每 region 一筆，`enabled` 布林),`enabled != true` 即 deny。`_name` 放 region 名，報告可讀。
