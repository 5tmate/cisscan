# cisscan

以 OPA/Rego 對 live AWS 帳號做 CIS AWS Foundations Benchmark v5.0.0 合規檢查。

## 架構

```
collector(可抽換)                     核心
┌ terraformer dump(現況)┐
│ boto3 API collector(P2)├──→ resources.json ──→ opa eval(rules/)──→ 報告
└ …                      ┘      (中間格式)
```

- **規則層先行完成**:v5.0.0 全部 40 條控制的 rego 已就位(`rules/`)，包含需要 credential report 等帳號級資料的 14 條，collector 之後補上資料，規則直接生效。
- **中間格式是合約**:`{"meta": {...}, "resources": [{"_type": "aws_...", ...}]}`，欄位採 Terraform schema 命名。詳見 `docs/CONTROLS.md` 的「輸入合約」。
- **collected_types 閘門**:「必須存在某資源」類控制只在 collector 宣告收集過該型別時才判，看不到的東西不報違規。

## 使用

```bash
opa test rules/          # 跑全部規則測試(119 個)
```

規則包合約:每個 package 輸出 `titles` / `cis_requirements` / `severities` / `enforced` / `applicable` / `deny`，報告層據此區分 pass / FAIL / n/a。

## 文件

- `controls/README.md`：共用規格:依據來源、輸入合約、規則包合約、資料來源總表
- `controls/<控制ID>.md`：每條規則一份說明:AWS 原文判定、我們的實作、資料來源、差異與理由
- `docs/`：本地參考資料(AWS 原文存檔、Security Hub API 定義)，不進版控

## Roadmap

1. **P1**:tfstate → 中間格式的 transformer，對 terraformer dump 跑出第一份報告
2. **P2**:boto3 collector，credential report、密碼政策、root MFA、PAB、flow logs 等 API 型資料
3. **P3**:報告輸出(terminal 摘要 + 靜態 HTML)
