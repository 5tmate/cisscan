# RDS.3：RDS 靜態加密(CIS 2.2.1，Medium)

- **AWS 判定**:「checks whether storage encryption is enabled for your Amazon RDS DB instances.」
- **我們的實作**:`storage_encrypted != true` → deny。
