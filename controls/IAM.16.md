# IAM.16：密碼政策防止重複使用(CIS 1.8，Low)

- **AWS 判定**:「checks whether the number of passwords to remember is set to 24. The control fails if the value is not 24.」
- **我們的實作**:`password_reuse_prevention >= 24`。AWS 說「必須是 24」而該欄位上限就是 24，故 `>= 24` 與 `== 24` 等價，無政策同樣 deny。
