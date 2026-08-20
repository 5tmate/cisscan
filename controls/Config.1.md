# Config.1：AWS Config 必須啟用且用 service-linked role(CIS 3.3，Critical)`cis_config.rego`

- **AWS 判定**:「checks whether AWS Config is enabled…records all resources…and uses the service-linked AWS Config role(AWSServiceRoleForConfig)」。
- **我們的實作**:三段 deny，(1) 收集過但無任何 `aws_config_configuration_recorder`，(2) recorder 的 `role_arn` 不含 `AWSServiceRoleForConfig`，(3) `recording_group.all_supported == false` 或對應 `aws_config_configuration_recorder_status.is_enabled == false`。
- **差異**:AWS 的完整邏輯還分 aggregation region 與 IAM 全域資源錄製的細節，我們做的是單帳號全掃視角的等價簡化(recorder 存在 + 錄全部 + service-linked role + 啟用中)，並在訊息中指出失敗原因。
