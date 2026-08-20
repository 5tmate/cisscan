# CloudTrail.7：CloudTrail 的 S3 bucket 必須開 access logging(CIS 3.4，Low)

- **AWS 判定**:「Security Hub first uses custom logic to look for the S3 bucket where your CloudTrail logs are stored, then checks if logging is enabled.」且明文:集中式跨帳號 log bucket 只在 bucket 所在帳號評估，其他帳號為 No data。
- **我們的實作**:對每條 trail 的 `s3_bucket_name`，在輸入中找同名 `aws_s3_bucket`，檢查其 `logging` 屬性非空、或存在對應的 `aws_s3_bucket_logging` 資源。**bucket 不在輸入中(跨帳號)→ 不判**，正對應 AWS 的 No data 行為。
