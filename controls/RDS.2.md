# RDS.2：RDS 不得公開存取(CIS 2.2.3，Critical)`cis_rds.rego`

- **AWS 判定**:「evaluating the `PubliclyAccessible` field in the instance configuration item.」
- **我們的實作**:`aws_db_instance.publicly_accessible == true` → deny。
