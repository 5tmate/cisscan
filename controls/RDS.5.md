# RDS.5：RDS instance 必須 Multi-AZ(CIS 2.2.4，Medium)

- **AWS 判定**:「fails if an RDS DB instance isn't configured with multiple AZs. This control doesn't apply to RDS DB instances that are part of a Multi-AZ DB cluster deployment.」
- **我們的實作**:只判 `aws_db_instance` 的 `multi_az != true`。cluster 成員在 Terraform schema 中是 `aws_rds_cluster_instance`，天然排除，正好對應原文的豁免。
