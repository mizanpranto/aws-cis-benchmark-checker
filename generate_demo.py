"""
CIS Benchmark Checker — Demo Report Generator
Generates a realistic sample PDF with mock results.
No AWS credentials needed.

Usage: python generate_demo.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from cis_checker import generate_pdf, calc_score, CONTROLS

CONSULTANT = {
    "name":  "Your Name",
    "title": "Cloud Security Consultant",
    "email": "hello@yoursite.com",
    "certs": "AWS SAA Certified | ISO 27001 | NIST | GDPR",
}
CLIENT = {"name": "FinVault Technologies Ltd", "industry": "Fintech / SaaS", "contact": "CTO"}
CREDS  = {"account_id": "234567890123", "region": "us-east-1"}

# Realistic results — a typical startup that hasn't hardened AWS yet
MOCK_RESULTS = {
    # IAM — mostly failing
    "1.1":  {"status":"FAIL",  "detail":"Root account MFA is NOT enabled."},
    "1.2":  {"status":"FAIL",  "detail":"Root account has active access keys — DELETE IMMEDIATELY."},
    "1.3":  {"status":"FAIL",  "detail":"Users without MFA: john.dev, sara.ops, admin-deploy, ci-pipeline"},
    "1.4":  {"status":"FAIL",  "detail":"Root has active access keys — DELETE IMMEDIATELY."},
    "1.5":  {"status":"FAIL",  "detail":"Min length: 8 (required: 14)"},
    "1.6":  {"status":"FAIL",  "detail":"Uppercase NOT required."},
    "1.7":  {"status":"PASS",  "detail":"Lowercase required."},
    "1.8":  {"status":"FAIL",  "detail":"Numbers NOT required."},
    "1.9":  {"status":"FAIL",  "detail":"Symbols NOT required."},
    "1.10": {"status":"FAIL",  "detail":"Reuse prevention: 0 (required: 24)"},
    "1.11": {"status":"FAIL",  "detail":"Max age: Not set (required: ≤90 days)"},
    "1.12": {"status":"FAIL",  "detail":"Stale credentials (90+ days unused): john.dev, old-svc-account, temp-user"},
    "1.13": {"status":"FAIL",  "detail":"Users with AdministratorAccess: john.dev, ci-deploy-user"},
    "1.14": {"status":"FAIL",  "detail":"No active IAM Access Analyzers found."},
    # S3 — mixed
    "2.1":  {"status":"FAIL",  "detail":"BPA: BlockAcls=False IgnoreAcls=False BlockPolicy=False Restrict=False"},
    "2.2":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [3/8]: finvault-prod-customer-documents, finvault-staging-uploads, finvault-static-website"},
    "2.3":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [2/8]: finvault-prod-customer-documents, finvault-dev-test-data"},
    "2.4":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [6/8]: finvault-prod-customer-documents, finvault-prod-database-backups, finvault-staging-uploads, finvault-dev-test-data, finvault-prod-invoices..."},
    "2.5":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [7/8]: all except finvault-prod-app-assets"},
    "2.6":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [7/8]: logging disabled on all production buckets"},
    "2.7":  {"status":"PASS",  "detail":"All 8 bucket(s) passed this check."},
    "2.8":  {"status":"FAIL",  "detail":"Non-compliant bucket(s) [6/8]: no lifecycle rules configured"},
    # Logging
    "3.1":  {"status":"FAIL",  "detail":"No multi-region CloudTrail trail found."},
    "3.2":  {"status":"FAIL",  "detail":"Trails without validation: finvault-trail"},
    "3.3":  {"status":"FAIL",  "detail":"CloudTrail bucket(s) not fully protected: finvault-cloudtrail-logs"},
    "3.4":  {"status":"FAIL",  "detail":"Trails without KMS encryption: finvault-trail"},
    "3.5":  {"status":"FAIL",  "detail":"AWS Config not configured in this region."},
    "3.6":  {"status":"FAIL",  "detail":"CloudTrail buckets without access logging: finvault-cloudtrail-logs"},
    "3.7":  {"status":"FAIL",  "detail":"VPCs without flow logs: vpc-0a1b2c3d (us-east-1), vpc-1a2b3c4d (ap-southeast-1)"},
    "3.8":  {"status":"FAIL",  "detail":"Trails not sending to CloudWatch: finvault-trail"},
    # Monitoring
    "4.1":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'UnauthorizedOperation'."},
    "4.2":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'userIdentity.type = Root'."},
    "4.3":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'DeleteGroupPolicy'."},
    "4.4":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'DeleteTrail'."},
    "4.5":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'PutBucketPolicy'."},
    "4.6":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'AuthorizeSecurityGroupIngress'."},
    "4.7":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'CreateNetworkAcl'."},
    "4.8":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'CreateCustomerGateway'."},
    "4.9":  {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'CreateVpc'."},
    "4.10": {"status":"FAIL",  "detail":"GuardDuty is not enabled in this region."},
    "4.11": {"status":"FAIL",  "detail":"AWS Security Hub is not enabled."},
    "4.12": {"status":"FAIL",  "detail":"No CloudWatch metric filter found for 'ConsoleLogin'."},
    # Networking — partially compliant
    "5.1":  {"status":"FAIL",  "detail":"Security groups open to internet: sg-0a1b2c3d (us-east-1), sg-1a2b3c4d (us-east-1)"},
    "5.2":  {"status":"FAIL",  "detail":"Security groups open to internet: sg-0a1b2c3d (us-east-1)"},
    "5.3":  {"status":"PASS",  "detail":"No security groups with all-traffic inbound found."},
    "5.4":  {"status":"FAIL",  "detail":"Default SGs with rules: vpc-0a1b2c3d (us-east-1), vpc-1a2b3c4d (ap-southeast-1)"},
    "5.5":  {"status":"FAIL",  "detail":"Default VPCs with subnets (in use): vpc-0a1b2c3d (us-east-1), vpc-1a2b3c4d (ap-southeast-1)"},
    "5.6":  {"status":"PASS",  "detail":"No overly permissive VPC peering routes found."},
}

if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║   CIS BENCHMARK CHECKER — DEMO REPORT GENERATOR        ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    summary = calc_score(MOCK_RESULTS)

    print(f"  Client     : {CLIENT['name']}")
    print(f"  Controls   : {summary['total']}")
    print(f"  Passed     : {summary['passed']}")
    print(f"  Failed     : {summary['failed']}")
    print(f"  Score      : {summary['score']}/100 — {summary['rating']}")
    print(f"\n  ⏳ Generating PDF...\n")

    output = "cis_report_finvault_DEMO.pdf"
    generate_pdf(output, CONSULTANT, CLIENT, CREDS, MOCK_RESULTS, summary)

    print(f"  ✅ Done: {output}")
    print(f"\n  Pin this on GitHub. Send to prospects.")
    print(f"  Shows clients exactly what their CIS compliance looks like.\n")
