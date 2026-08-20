# IAM.22：45 天未使用的憑證必須移除(CIS 1.11，Medium)

- **AWS 判定**:「checks whether your IAM users have passwords or active access keys that have not been used for 45 days or more」，原文注明使用 credential report。
- **我們的實作**:非 root 列，(a) `password_enabled` 且 `password_last_used` 早於 45 天(若從未使用過即為 `N/A`，退回看 `password_last_changed`)，(b) 任一 active key 的 `access_key_{N}_last_used_date` 早於 45 天(從未使用退回 `last_rotated`)。
- **理由**:fallback 邏輯對應 Config rule 的實際行為，「建立後從未用過且已超過 45 天」也算 unused，否則從不登入的殭屍帳號永遠不會被抓到。
