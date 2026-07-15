# 📋 AWS CIS Benchmark Checker

> **Checks your AWS account against the CIS AWS Foundations Benchmark v1.5**  
> 50 controls · 5 sections · Interactive wizard · Professional PDF compliance report  
> Built for cloud security consultants delivering compliance assessments to startups and SMEs.

---

## 📋 What It Does

Run one command. Enter credentials step by step. Receive a full compliance report.

The checker evaluates your AWS environment against **50 CIS AWS Foundations Benchmark v1.5 controls** across 5 domains and generates a branded PDF report showing exactly where you pass, fail, and what to fix.

---

## 🔍 Controls Covered — 50 Across 5 Sections

### 🔴 Section 1 — IAM (14 controls)
| ID | Control |
|----|---------|
| 1.1 | Root account MFA enabled |
| 1.2 | Root account has no active access keys |
| 1.3 | MFA enabled for all IAM users with console access |
| 1.4 | No access keys for root account |
| 1.5 | IAM password policy requires minimum 14 characters |
| 1.6 | IAM password policy requires uppercase letters |
| 1.7 | IAM password policy requires lowercase letters |
| 1.8 | IAM password policy requires numbers |
| 1.9 | IAM password policy requires symbols |
| 1.10 | IAM password policy prevents password reuse (24) |
| 1.11 | IAM password expires within 90 days |
| 1.12 | No unused IAM credentials for 90+ days |
| 1.13 | No IAM users with AdministratorAccess policy |
| 1.14 | IAM Access Analyzer enabled |

### 🟠 Section 2 — S3 (8 controls)
| ID | Control |
|----|---------|
| 2.1 | S3 Block Public Access enabled at account level |
| 2.2 | No S3 buckets with public ACLs |
| 2.3 | No S3 buckets with public bucket policies |
| 2.4 | S3 buckets have default encryption enabled |
| 2.5 | S3 buckets deny HTTP access (enforce HTTPS) |
| 2.6 | S3 bucket access logging enabled |
| 2.7 | S3 buckets have versioning enabled |
| 2.8 | S3 buckets have lifecycle policies |

### 🔵 Section 3 — Logging (8 controls)
| ID | Control |
|----|---------|
| 3.1 | CloudTrail enabled in all regions |
| 3.2 | CloudTrail log file validation enabled |
| 3.3 | CloudTrail S3 bucket not publicly accessible |
| 3.4 | CloudTrail logs encrypted with KMS |
| 3.5 | AWS Config enabled in all regions |
| 3.6 | CloudTrail S3 bucket has access logging enabled |
| 3.7 | VPC Flow Logs enabled in all VPCs |
| 3.8 | CloudTrail integrated with CloudWatch Logs |

### 🟣 Section 4 — Monitoring (12 controls)
| ID | Control |
|----|---------|
| 4.1 | Alarm for unauthorized API calls |
| 4.2 | Alarm for root account usage |
| 4.3 | Alarm for IAM policy changes |
| 4.4 | Alarm for CloudTrail configuration changes |
| 4.5 | Alarm for S3 bucket policy changes |
| 4.6 | Alarm for security group changes |
| 4.7 | Alarm for NACL changes |
| 4.8 | Alarm for network gateway changes |
| 4.9 | Alarm for VPC changes |
| 4.10 | AWS GuardDuty enabled |
| 4.11 | AWS Security Hub enabled |
| 4.12 | Alarm for console sign-in without MFA |

### 🟢 Section 5 — Networking (6 controls)
| ID | Control |
|----|---------|
| 5.1 | No security groups allow SSH from 0.0.0.0/0 |
| 5.2 | No security groups allow RDP from 0.0.0.0/0 |
| 5.3 | No security groups allow all traffic inbound |
| 5.4 | Default VPC security group blocks all traffic |
| 5.5 | No unused default VPC in any region |
| 5.6 | VPC peering does not allow overly permissive routing |

---

## 📄 Report Sections

The generated PDF contains:

1. **Cover page** — client name, AWS account, scan date, compliance score, consultant credentials
2. **Executive summary** — narrative + compliance score box with passed/failed counts
3. **Section scores** — compliance % per domain with COMPLIANT / PARTIAL / NON-COMPLIANT status
4. **IAM results** — all 14 IAM controls with pass/fail per control
5. **S3 results** — all 8 S3 controls with pass/fail per control
6. **Logging results** — all 8 Logging controls with pass/fail
7. **Monitoring results** — all 12 Monitoring controls with pass/fail
8. **Networking results** — all 6 Networking controls with pass/fail
9. **Failed controls** — detailed finding cards for every failed control with remediation steps
10. **Remediation roadmap** — phased fix plan grouped by domain priority
11. **Appendix** — full reference table of all 50 controls with status

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install boto3 reportlab

# 2. Run the checker
python cis_checker.py

# 3. Follow the wizard — PDF generated automatically
```

---

## 🖥️ Wizard Walkthrough

```
╔══════════════════════════════════════════════════════════╗
║     AWS CIS BENCHMARK CHECKER v1.5                     ║
║     Cloud Security Consultant Tool                     ║
╚══════════════════════════════════════════════════════════╝
  50 controls · 5 sections · IAM · S3 · Logging · Monitoring · Networking

──────────────────────────────────────────────────────────
  STEP 1 of 3 — YOUR CONSULTANT DETAILS
──────────────────────────────────────────────────────────
  Your full name [Your Name]: Mohammed Rahman
  Your title: Cloud Security Consultant
  Your email: hello@yoursite.com
  Your certifications: AWS SAA Certified | ISO 27001 | NIST | GDPR

──────────────────────────────────────────────────────────
  STEP 2 of 3 — CLIENT DETAILS
──────────────────────────────────────────────────────────
  Client company name: FinVault Technologies Ltd
  Client industry: Fintech / SaaS

──────────────────────────────────────────────────────────
  STEP 3 of 3 — AWS CREDENTIALS
──────────────────────────────────────────────────────────
  AWS Access Key ID: ****************
  AWS Secret Access Key: ****************
  Default region [us-east-1]:
  AWS Account ID: 234567890123

──────────────────────────────────────────────────────────
  RUNNING CIS CHECKS
──────────────────────────────────────────────────────────
  [50/50]  5.6    VPC peering does not allow overly permissive routing
  ✓ Completed 50 checks — 6 passed · 44 failed · 0 errors

──────────────────────────────────────────────────────────
  GENERATING PDF REPORT
──────────────────────────────────────────────────────────
  Compliance Score : 8/100 — NON-COMPLIANT
  Controls Passed  : 6 / 50
  Controls Failed  : 44
  Output           : cis_report_finvault_20260703.pdf

╔══════════════════════════════════════════════════════════╗
║  ✅ REPORT READY: cis_report_finvault_20260703.pdf      ║
╚══════════════════════════════════════════════════════════╝
```

---

## 📊 Compliance Score

```
Controls Passed
─────────────── × 100 = Compliance Score
 Total Controls
```

| Score | Rating |
|-------|--------|
| 90–100 | ✅ COMPLIANT |
| 75–89 | 🟡 MOSTLY COMPLIANT |
| 50–74 | 🟠 PARTIALLY COMPLIANT |
| 0–49 | 🔴 NON-COMPLIANT |

---

## 🔑 Required IAM Permissions

Read-only — the checker **never modifies** your AWS environment.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListLoginProfiles",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "access-analyzer:ListAnalyzers",
        "s3:GetPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketLifecycleConfiguration",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVpcPeeringConnections",
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "securityhub:DescribeHub"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 🧪 Try Without AWS Credentials

See the full report format using mock data — no AWS account needed:

```bash
python generate_demo.py
# Output: cis_report_finvault_DEMO.pdf
```

---

## 📁 Project Structure

```
aws-cis-benchmark-checker/
├── cis_checker.py              # Main checker + PDF generator (run this)
├── generate_demo.py            # Demo with mock data — no AWS needed
├── cis_report_finvault_DEMO.pdf  # Sample output
└── README.md                   # This file
```

---

## 💼 How This Fits Your Consulting Workflow

```
Client needs SOC 2, ISO 27001, or PCI-DSS compliance
                    ↓
You create read-only IAM credentials in their account
                    ↓
python cis_checker.py → wizard → PDF in minutes
                    ↓
Deliver compliance report — charge $5,000–$15,000
                    ↓
Offer remediation retainer to fix all failed controls
($3,000–$5,000/month ongoing)
```

---

## 🔗 Part of the AWS Security Consultant Toolkit

| Tool | Purpose | GitHub |
|------|---------|--------|
| `aws-security-assessment-report-template` | Manual findings → professional PDF | [→](#) |
| `s3-exposure-scanner` | Automated S3 security scan | [→](#) |
| `aws-cis-benchmark-checker` | Full CIS v1.5 compliance check | **You are here** |
| `iam-privilege-escalation-detector` | IAM attack path analysis | [→](#) |
| `secure-aws-baseline` | Terraform hardened baseline | [→](#) |

---

## 👤 About

Built by **[Your Name]** — Cloud Security Consultant  
Specialising in AWS security assessments and compliance for startups and SMEs globally.

- 🌐 [yourwebsite.com](https://yourwebsite.com)
- 💼 [LinkedIn](https://linkedin.com/in/yourhandle)
- 📧 hello@yoursite.com
- 🏅 AWS SAA Certified | ISO 27001 | NIST | GDPR

**Available for CIS Benchmark Assessments** — [Book a free 30-min call](mailto:hello@yoursite.com)

---

## ⚠️ Disclaimer

For use by qualified security consultants only. The checker is read-only and does not modify any AWS resources. Results reflect the state of the environment at time of assessment. Re-assess after remediation to verify improvements. Sample outputs use fictional data.
