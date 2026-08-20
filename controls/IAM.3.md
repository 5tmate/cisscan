# IAM.3：access key 90 天內必須輪替(CIS 1.13，Medium)

- **AWS 判定**:「checks whether the active access keys are rotated within 90 days」(rule `access-keys-rotated`,`maxAccessKeyAge: 90` 不可自訂)。
- **我們的實作**:credential report 每列的 `access_key_{1,2}_active == true` 且 `access_key_{N}_last_rotated` 早於 `scanned_at - 90d` → deny。非啟用的 key 不判(原文限定 active)。root 列不在此控制範圍(root key 由 IAM.4 管)。
