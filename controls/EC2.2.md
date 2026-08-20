# EC2.2：default security group 不得允許任何流量(CIS 5.5，High)`cis_ec2.rego`

- **AWS 判定**:「The control fails if the security group allows inbound or outbound traffic.」(rule `vpc-default-security-group-closed`)
- **我們的實作**:`name == "default"` 的 `aws_security_group`,`ingress` + `egress` 條數 > 0 即 deny。一比一對應。
