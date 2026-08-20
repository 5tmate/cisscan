# cisscan

以 OPA/Rego 對 live AWS 帳號做 CIS AWS Foundations Benchmark v5.0.0 合規檢查。

## 架構

```
scanner/(我們自己的掃描器)     adapters/(來源格式 → 固定 json)      核心
┌ aws_api.py(打 AWS API)─────→ aws_response.py                 ┐
│                              terraformer.py(吃 tfstate dump)├→ resources.json → report.py(opa eval rules/)→ 報告
│                              pulumi.py(未來，吃 state)      │     (中間格式)
└                              document.py(共用組件)          ┘
```

- **規則層先行完成**:v5.0.0 全部 40 條控制的 rego 已就位(`rules/`)，包含需要 credential report 等帳號級資料的 14 條，collector 之後補上資料，規則直接生效。
- **中間格式是合約**:`{"meta": {...}, "resources": [{"_type": "aws_...", ...}]}`，欄位採 Terraform schema 命名。詳見 `controls/README.md` 的「輸入合約」。
- **collected_types 閘門**:「必須存在某資源」類控制只在 collector 宣告收集過該型別時才判，看不到的東西不報違規。

## 使用

```bash
uv run python cisscan.py --profile <profile>                  # 一鍵：掃描 + 評估 + 報告
uv run python cisscan.py --from-terraformer <dump目錄>        # 一鍵：吃現成 dump + 評估 + 報告

opa test rules/          # 跑全部規則測試
uv run pytest            # scanner、adapters、報告層測試

uv run python -m scanner.aws_api --profile <profile> -o out/resources.json   # 只掃描
uv run python report.py out/resources.json                                   # 只評估
```

職責劃分：`scanner/` 是我們自己的掃描器，只負責呼叫 AWS API；`adapters/` 是格式轉換層，每個模組把一種來源的資料整形成中間格式（欄位翻成 Terraform 命名、型別正確、`collected_types` 誠實申報），共用的組文件與輸出邏輯在 `adapters/document.py`。新資料來源＝新增一個 adapter，規則層零修改。

規則包合約:每個 package 輸出 `titles` / `cis_requirements` / `severities` / `enforced` / `applicable` / `deny`，報告層據此區分 pass / FAIL / n/a。

## 文件

- `controls/README.md`：共用規格:依據來源、輸入合約、規則包合約、資料來源總表
- `controls/<控制ID>.md`：每條規則一份說明:AWS 原文判定、我們的實作、資料來源、差異與理由
- `docs/`：本地參考資料(AWS 原文存檔、Security Hub API 定義)，不進版控

## Roadmap

1. **P1**:tfstate → 中間格式的 transformer，對 terraformer dump 跑出第一份報告
2. **P2**:boto3 collector，credential report、密碼政策、root MFA、PAB、flow logs 等 API 型資料
3. **P3**:報告輸出(terminal 摘要 + 靜態 HTML)
