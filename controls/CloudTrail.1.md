# CloudTrail.1：至少一條 multi-Region trail 記錄讀寫管理事件(CIS 3.1，High)`cis_cloudtrail.rego`

- **AWS 判定**:「fails if CloudTrail is disabled or if there isn't at least one CloudTrail trail that captures read and write management events」，並要求 multi-Region(Config rule `multi-region-cloudtrail-enabled`，參數 `readWriteType: ALL`、`includeManagementEvents: true`)。
- **我們的實作**:帳號級檢查。存在一條 trail 同時滿足:`is_multi_region_trail == true`、`enable_logging != false`、管理事件全記錄，即(a)完全沒設 event selector(CloudTrail 預設記錄全部管理事件)，或(b)某 `event_selector` 的 `include_management_events == true` 且 `read_write_type == "All"`，或(c)某 `advanced_event_selector` 選了 `eventCategory = Management` 且沒有 `readOnly` 限制欄位。
- **理由**:(a) 對應 CloudTrail API 預設值，(c) 是 advanced selector 語意，一旦出現 readOnly 欄位就表示只記錄單向，不符「read and write」。
