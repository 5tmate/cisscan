# 規則對照說明(共用規格)

本文件逐條說明 `rules/` 下每條 rego 規則的判定邏輯如何對應 AWS Security Hub 的控制定義、需要哪些輸入資料、以及與 AWS 行為的差異和理由。

## 依據來源

1. **控制清單與 CIS 條號對照**:[CIS AWS Foundations Benchmark in Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)(v5.0.0 共 40 條控制)
2. **每條控制的完整判定說明**:Security Hub 各 service 控制頁(`cloudtrail-controls.html`、`ec2-controls.html`、`iam-controls.html`、`s3-controls.html` 等),EC2 頁完整原文存於 `docs/ec2-controls.txt`
3. **權威 severity 與描述**:Security Hub API `GetSecurityControlDefinition` 的即時查詢結果，存於 `docs/securityhub_definitions.json`(2026-08-20 取得)

嚴重度(severity)一律以 API 回傳值為準，過程中發現網頁摘要與 API 不一致時(如 EC2.53)，以 API 為準。

## 輸入合約

規則吃單一 JSON 文件:

```json
{
  "meta": {
    "account_id": "123456789012",
    "scanned_at": "2026-08-20T00:00:00Z",
    "collected_types": ["aws_s3_bucket", "aws_cloudtrail", "..."]
  },
  "resources": [
    {"_type": "aws_security_group", "_name": "web", "_region": "ap-northeast-1", "...": "Terraform 屬性名(snake_case),布林與數字為原生型別"}
  ]
}
```

- `_type` 採 **Terraform 資源型別名**(`aws_instance`、`aws_s3_bucket`…)。理由:terraformer dump 原生就是這個 schema，而未來自寫的 boto3 collector 只要正規化成同一名字空間，規則層完全不用動。
- 沒有對應 Terraform 資源的帳號級事實，定義**合成型別**(見下方資料來源表)，欄位名沿用該資料的 AWS 原始欄位(credential report 的 CSV 欄名、API 回傳欄名)。
- `meta.scanned_at`:掃描時刻(RFC3339)。所有涉及時間的控制(IAM.3/22/26)以它為「現在」，確保同一份輸入重跑結果相同。
- `meta.collected_types`:collector 宣告「我去看過哪些型別」。**「必須存在某資源」類的控制只在該型別被宣告收集過時才判**，collector 沒去看的東西，「看不到」絕不能報成違規。這直接沿用 infra CI gate 的設計哲學(gate 從不把 preview 看不到的東西當 FAIL)。

## 規則包合約

每個 package 輸出:`titles`(控制 → 標題)、`cis_requirements`(控制 → CIS v5.0 條號)、`severities`、`enforced`、`applicable`(檢查過的資源)、`deny`(違規)。`applicable` 與 `deny` 的配對讓報告能區分 **pass(檢查過且合規)/ FAIL / n/a(無此類資源或未收集)**，綠燈永遠不含糊。

## 資料來源總表

| 輸入 `_type` | 提供者 | 來源 |
|---|---|---|
| `aws_cloudtrail`, `aws_s3_bucket`, `aws_s3_bucket_policy`, `aws_s3_bucket_logging`, `aws_security_group`, `aws_network_acl`, `aws_vpc`, `aws_instance`, `aws_efs_file_system`, `aws_kms_key`, `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance`, `aws_iam_user`, `aws_iam_user_policy`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_iam_role_policy_attachment`, `aws_accessanalyzer_analyzer`, `aws_config_configuration_recorder(_status)` | terraformer dump(P1 已可用)或 API collector | Terraform state |
| `aws_iam_credential_report_user`(合成，每個 user 一筆，含 `<root_account>` 列) | API collector(P2) | `iam:GenerateCredentialReport` + `GetCredentialReport`(CSV 欄名照搬) |
| `aws_iam_account_password_policy` | API collector(P2) | `iam:GetAccountPasswordPolicy` |
| `aws_iam_virtual_mfa_device` | API collector(P2) | `iam:ListVirtualMFADevices` |
| `aws_iam_server_certificate` | API collector(P2) | `iam:ListServerCertificates` |
| `aws_ebs_encryption_by_default`(合成，每 region 一筆) | API collector(P2) | `ec2:GetEbsEncryptionByDefault` |
| `aws_flow_log` | API collector(P2，terraformer 不匯出) | `ec2:DescribeFlowLogs` |
| `aws_s3_account_public_access_block` | API collector(P2) | `s3control:GetPublicAccessBlock` |
| `aws_s3_bucket_public_access_block` | API collector(P2，terraformer 不匯出) | `s3:GetBucketPublicAccessBlock` |
| `aws_account_alternate_contact` | API collector(P2) | `account:GetAlternateContact(SECURITY)` |

---

## 逐條說明索引

- [Account.1](Account.1.md)
- [CloudTrail.1](CloudTrail.1.md)
- [CloudTrail.2](CloudTrail.2.md)
- [CloudTrail.4](CloudTrail.4.md)
- [CloudTrail.7](CloudTrail.7.md)
- [Config.1](Config.1.md)
- [EC2.2](EC2.2.md)
- [EC2.6](EC2.6.md)
- [EC2.7](EC2.7.md)
- [EC2.8](EC2.8.md)
- [EC2.21](EC2.21.md)
- [EC2.53 / EC2.54](EC2.53_EC2.54.md)
- [EFS.1 / EFS.8](EFS.1_EFS.8.md)
- [IAM.2](IAM.2.md)
- [IAM.3](IAM.3.md)
- [IAM.4](IAM.4.md)
- [IAM.5](IAM.5.md)
- [IAM.6](IAM.6.md)
- [IAM.9](IAM.9.md)
- [IAM.15](IAM.15.md)
- [IAM.16](IAM.16.md)
- [IAM.18](IAM.18.md)
- [IAM.22](IAM.22.md)
- [IAM.26](IAM.26.md)
- [IAM.27](IAM.27.md)
- [IAM.28](IAM.28.md)
- [KMS.4](KMS.4.md)
- [RDS.2](RDS.2.md)
- [RDS.3](RDS.3.md)
- [RDS.5](RDS.5.md)
- [RDS.13](RDS.13.md)
- [RDS.15](RDS.15.md)
- [S3.1](S3.1.md)
- [S3.5](S3.5.md)
- [S3.8](S3.8.md)
- [S3.20](S3.20.md)
- [S3.22 / S3.23](S3.22_S3.23.md)

## 測試

每條控制在 `rules/*_test.rego` 中至少有一組 fail 案例與一組 pass 案例(共 119 個測試)，以 TDD 流程寫成:先寫測試確認全數 FAIL，再實作規則至全數 PASS。執行:

```bash
opa test rules/
```
