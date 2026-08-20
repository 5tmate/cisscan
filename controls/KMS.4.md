# KMS.4：KMS key 必須開自動輪替(CIS 3.6，Medium)`cis_kms.rego`

- **AWS 判定**:「AWS KMS enables customers to rotate the backing key…CIS recommends that you enable KMS key rotation.」(rule `cmk-backing-key-rotation-enabled`)
- **我們的實作**:只判對稱加密 key(`customer_master_key_spec == SYMMETRIC_DEFAULT` 且 `key_usage == ENCRYPT_DECRYPT`，缺欄位視為預設值即對稱),`enable_key_rotation != true` → deny。
- **理由**:KMS 自動輪替僅支援對稱加密 key，非對稱/簽章 key 判 FAIL 是物理上無法修復的假警報，故列為不適用(n/a)。
