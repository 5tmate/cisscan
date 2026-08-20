# CloudTrail.4：開啟 log file validation(CIS 3.2，Low)

- **AWS 判定**:「checks whether log file integrity validation is enabled on a CloudTrail trail.」
- **我們的實作**:逐 trail 檢查 `enable_log_file_validation == true`(Terraform 預設 false，故缺欄位視為未開)。一比一對應。
