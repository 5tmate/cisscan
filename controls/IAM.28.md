# IAM.28：必須啟用 Access Analyzer 外部存取分析器(CIS 1.19，High)

- **AWS 判定**:「The control fails if the account doesn't have an external access analyzer enabled in your currently selected Region.」
- **我們的實作**:存在 `type ∈ {ACCOUNT, ORGANIZATION}` 的 `aws_accessanalyzer_analyzer` → pass。`ACCOUNT_UNUSED_ACCESS` 型(unused access analyzer)不算，原文限定 external access analyzer。
- **刻意差異**:AWS 逐 region 判，我們做全帳號視角(任一 region 有即 pass)。全帳號掃描器逐 region 產 40 × N 條結果噪音太大，先取帳號級語意，per-region 嚴格模式留給之後的參數。
