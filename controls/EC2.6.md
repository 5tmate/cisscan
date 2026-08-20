# EC2.6：所有 VPC 必須開 flow log(CIS 3.7，Medium)

- **AWS 判定**:「checks whether Amazon VPC Flow Logs are found and enabled for VPCs. The traffic type is set to Reject.」(rule `vpc-flow-logs-enabled`，參數 `trafficType: REJECT` 不可自訂)
- **我們的實作**:每個 `aws_vpc` 必須有 `vpc_id` 指向它的 `aws_flow_log`，且 `traffic_type ∈ {REJECT, ALL}`。
- **刻意差異**:AWS 嚴格只認 REJECT，我們額外接受 ALL，因為 ALL 是 REJECT 的嚴格超集(記錄了全部流量必然包含被拒流量)，判 FAIL 反而製造假警報。已知偏鬆一格，記錄於此。
- **閘門**:terraformer 不匯出 flow log，故 gated on `collected_types` 含 `aws_flow_log`,P2 collector 補上前此控制為 n/a 而非誤報。
