# RDS.15：RDS cluster 必須跨多 AZ(CIS 2.2.4，Medium)

- **AWS 判定**:「fails if an RDS DB cluster isn't deployed in multiple AZs.」
- **我們的實作(heuristic，明確標注)**:`aws_rds_cluster.availability_zones` 少於 2 個 → deny。Terraform schema 沒有 cluster 級的 multi-AZ 布林，Aurora cluster 預設宣告 3 個 AZ，即使實例只有一顆，此近似會偏鬆(Aurora 單實例 cluster 可能誤判 pass)。待 P2 collector 直接取 `DescribeDBClusters.MultiAZ` 欄位後改為精確判定。
