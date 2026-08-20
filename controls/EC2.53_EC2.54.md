# EC2.53 / EC2.54：SG 不得從 0.0.0.0/0(53)/ ::/0(54)開遠端管理 port(CIS 5.3 / 5.4，均 High)

- **AWS 判定**(完整原文，修正了早期摘要的錯誤):Config rule `vpc-sg-port-restriction-check`，參數 `restrictPorts: 22,3389`(不可自訂)、`ipType: IPv4/IPv6`。「using either the TDP (6), UDP (17), or ALL (-1) protocols」。
- **我們的實作**:`admin_ports := {22, 3389}`，協定接受 `tcp/udp/6/17/-1`，EC2.53 看 `cidr_blocks` 含 `0.0.0.0/0`,EC2.54 看 `ipv6_cidr_blocks` 含 `::/0`，port 範圍涵蓋即 deny。一比一對應。
- **註**:舊版控制曾用 24 個 port 的封鎖清單，v5.0 世代已改為只有 22/3389，這是「必須讀完整原文」的實證，摘要版給的是過時清單。
