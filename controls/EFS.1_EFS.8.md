# EFS.1 / EFS.8：EFS 必須靜態加密(CIS 2.3.1，均 Medium)`cis_efs.rego`

- **AWS 判定**:EFS.1「fails in the following cases: `Encrypted` is set to false」且原文明言「It only checks the value of Encrypted」，EFS.8「fails if a file system isn't encrypted」。兩條在 CIS v5.0 對映同一條 2.3.1(EFS.1 為 periodic 舊規、EFS.8 為 change-triggered 新規)。
- **我們的實作**:同一判定式 `encrypted != true`，同時產出兩個控制 ID 的結果，讓報告與 Security Hub 的清單一一對得上。
