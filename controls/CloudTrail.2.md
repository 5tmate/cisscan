# CloudTrail.2：trail 必須用 KMS 加密(CIS 3.5，Medium)

- **AWS 判定**:「The control fails if the `KmsKeyId` isn't defined.」
- **我們的實作**:逐 trail 檢查 `kms_key_id` 非空字串。一比一對應，無差異。
