# EC2.8：EC2 必須用 IMDSv2(CIS 5.7，High)

- **AWS 判定**:「The control passes if `HttpTokens` is set to required. The control fails if `HttpTokens` is set to optional.」
- **我們的實作**:`metadata_options[0].http_tokens == "required"` → pass，完全沒有 `metadata_options` → deny(AWS 舊 AMI 預設 optional)。
- **刻意差異**:`http_endpoint == "disabled"` 也算 pass，IMDS 整個關掉時不存在 v1 可被 SSRF 打，風險等價消除。此判法與 infra repo CI gate 的 `imdsv2.rego` 一致，兩處政策同判。
