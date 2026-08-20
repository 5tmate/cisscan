# RDS.13：自動小版本升級(CIS 2.2.2，High)

- **AWS 判定**:「fails if automatic minor version upgrades are not enabled.」
- **我們的實作**:`aws_db_instance` 與 `aws_rds_cluster_instance` 皆判(cluster 成員在 RDS API 中同樣是 DB instance),`auto_minor_version_upgrade != true` → deny，缺欄位視為 true(AWS 預設開)。
