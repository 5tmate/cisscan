# IAM.26：過期的 IAM SSL/TLS 憑證必須移除(CIS 1.18，Medium)

- **AWS 判定**:「The control fails if the expired SSL/TLS server certificate isn't removed.」
- **我們的實作**:`aws_iam_server_certificate.expiration` 早於 `scanned_at` → deny。
