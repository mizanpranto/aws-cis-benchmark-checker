"""
AWS CIS Benchmark Checker
==========================
Cloud Security Consultant Tool
Checks AWS account against CIS AWS Foundations Benchmark v1.5
Covers: IAM · S3 · Logging · Monitoring · Networking
Outputs a professional PDF compliance report.

Usage: python cis_checker.py
"""

import json
import sys
import re
from datetime import date, datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas

# ─────────────────────────────────────────────────────────────────────────────
# COLORS  (matches tool suite)
# ─────────────────────────────────────────────────────────────────────────────
DARK         = colors.HexColor("#0D1117")
GREEN        = colors.HexColor("#1D9E75")
GREEN_LIGHT  = colors.HexColor("#E1F5EE")
BLUE         = colors.HexColor("#185FA5")
BLUE_LIGHT   = colors.HexColor("#E3EEF9")
RED          = colors.HexColor("#C0392B")
RED_LIGHT    = colors.HexColor("#FCEBEB")
ORANGE       = colors.HexColor("#E67E22")
ORANGE_LIGHT = colors.HexColor("#FAEEDA")
PURPLE       = colors.HexColor("#6B63D4")
PURPLE_LIGHT = colors.HexColor("#EEEDFE")
GRAY         = colors.HexColor("#6E7681")
GRAY_LIGHT   = colors.HexColor("#F6F8FA")
WHITE        = colors.white

W_PAGE, H_PAGE = A4
MARGIN    = 14 * mm
CONTENT_W = W_PAGE - 2 * MARGIN

# ─────────────────────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────────────────────
def S(name, **kw):
    d = dict(fontName="Helvetica", fontSize=9.5,
             textColor=colors.HexColor("#24292F"), leading=14)
    d.update(kw)
    return ParagraphStyle(name, **d)

ST = {
    "cover_title": S("ct", fontName="Helvetica-Bold", fontSize=26, textColor=WHITE, leading=32),
    "cover_sub":   S("cs", fontSize=13, textColor=colors.HexColor("#9FE1CB"), leading=18),
    "cover_meta":  S("cm", fontSize=10, textColor=colors.HexColor("#8B949E"), leading=14),
    "cover_warn":  S("cw", fontName="Helvetica-Bold", fontSize=9, textColor=ORANGE, leading=12),
    "section":     S("sh", fontName="Helvetica-Bold", fontSize=14, textColor=DARK, spaceBefore=18, spaceAfter=10, leading=18),
    "body":        S("b",  fontSize=9.5, leading=14, spaceAfter=4),
    "small":       S("sm", fontSize=8.5, textColor=GRAY, leading=12),
    "label":       S("lb", fontName="Helvetica-Bold", fontSize=8, textColor=GRAY, leading=11),
    "mono":        S("mo", fontName="Courier", fontSize=8.5, textColor=DARK, leading=12),
    "toc":         S("tc", fontSize=10, textColor=BLUE, leading=16, leftIndent=10),
    "th":          S("th", fontName="Helvetica-Bold", fontSize=8.5, textColor=WHITE, leading=12),
    "td":          S("td", fontSize=8.5, textColor=colors.HexColor("#24292F"), leading=12),
    "td_mono":     S("tdm", fontName="Courier", fontSize=8, textColor=DARK, leading=11),
}

SECTION_COLORS = {
    "IAM":        (colors.HexColor("#C0392B"), colors.HexColor("#FCEBEB")),
    "S3":         (colors.HexColor("#E67E22"), colors.HexColor("#FAEEDA")),
    "Logging":    (colors.HexColor("#185FA5"), colors.HexColor("#E3EEF9")),
    "Monitoring": (colors.HexColor("#6B63D4"), colors.HexColor("#EEEDFE")),
    "Networking": (colors.HexColor("#1D9E75"), colors.HexColor("#E1F5EE")),
}

STATUS_COLORS = {
    "PASS":  GREEN,
    "FAIL":  RED,
    "ERROR": ORANGE,
    "N/A":   GRAY,
}

# ─────────────────────────────────────────────────────────────────────────────
# CIS CONTROLS  —  50 checks across 5 sections
# ─────────────────────────────────────────────────────────────────────────────
CONTROLS = [
    # ── IAM ──────────────────────────────────────────────────────────────────
    {"id":"1.1",  "section":"IAM", "title":"Root account MFA enabled",
     "description":"The root account should have MFA enabled to prevent unauthorized access.",
     "remediation":"Enable MFA on the root account via the AWS Console → Security Credentials.",
     "reference":"CIS AWS v1.5 — 1.5"},
    {"id":"1.2",  "section":"IAM", "title":"Root account has no active access keys",
     "description":"Root account access keys provide unrestricted access and should never exist.",
     "remediation":"Delete all root account access keys via IAM → Security Credentials.",
     "reference":"CIS AWS v1.5 — 1.4"},
    {"id":"1.3",  "section":"IAM", "title":"MFA enabled for all IAM users with console access",
     "description":"All IAM users with console access must have MFA enabled.",
     "remediation":"Enable MFA for each IAM user. Enforce via IAM policy condition aws:MultiFactorAuthPresent.",
     "reference":"CIS AWS v1.5 — 1.10"},
    {"id":"1.4",  "section":"IAM", "title":"No access keys for root account",
     "description":"Root account should not have active or inactive programmatic access keys.",
     "remediation":"Delete all root access keys. Use IAM users with least-privilege instead.",
     "reference":"CIS AWS v1.5 — 1.4"},
    {"id":"1.5",  "section":"IAM", "title":"IAM password policy requires minimum 14 characters",
     "description":"Password policy must require at least 14 characters.",
     "remediation":"Update IAM account password policy to require minimum 14 characters.",
     "reference":"CIS AWS v1.5 — 1.8"},
    {"id":"1.6",  "section":"IAM", "title":"IAM password policy requires uppercase letters",
     "description":"Password policy must require at least one uppercase letter.",
     "remediation":"Update IAM account password policy to require uppercase letters.",
     "reference":"CIS AWS v1.5 — 1.9"},
    {"id":"1.7",  "section":"IAM", "title":"IAM password policy requires lowercase letters",
     "description":"Password policy must require at least one lowercase letter.",
     "remediation":"Update IAM account password policy to require lowercase letters.",
     "reference":"CIS AWS v1.5 — 1.9"},
    {"id":"1.8",  "section":"IAM", "title":"IAM password policy requires numbers",
     "description":"Password policy must require at least one number.",
     "remediation":"Update IAM account password policy to require numbers.",
     "reference":"CIS AWS v1.5 — 1.9"},
    {"id":"1.9",  "section":"IAM", "title":"IAM password policy requires symbols",
     "description":"Password policy must require at least one symbol.",
     "remediation":"Update IAM account password policy to require symbols.",
     "reference":"CIS AWS v1.5 — 1.9"},
    {"id":"1.10", "section":"IAM", "title":"IAM password policy prevents password reuse (24)",
     "description":"Password policy must prevent reuse of the last 24 passwords.",
     "remediation":"Set password reuse prevention to 24 in IAM account password policy.",
     "reference":"CIS AWS v1.5 — 1.11"},
    {"id":"1.11", "section":"IAM", "title":"IAM password expires within 90 days",
     "description":"Passwords must expire within 90 days maximum.",
     "remediation":"Set max password age to 90 days in IAM account password policy.",
     "reference":"CIS AWS v1.5 — 1.11"},
    {"id":"1.12", "section":"IAM", "title":"No unused IAM credentials for 90+ days",
     "description":"IAM credentials unused for 90+ days should be disabled or removed.",
     "remediation":"Use IAM credential report to identify and disable stale credentials.",
     "reference":"CIS AWS v1.5 — 1.12"},
    {"id":"1.13", "section":"IAM", "title":"No IAM users with AdministratorAccess policy",
     "description":"Direct AdministratorAccess attachment to IAM users should be avoided.",
     "remediation":"Remove AdministratorAccess from IAM users. Use roles with least privilege instead.",
     "reference":"CIS AWS v1.5 — 1.16"},
    {"id":"1.14", "section":"IAM", "title":"IAM Access Analyzer enabled",
     "description":"IAM Access Analyzer identifies external access to AWS resources.",
     "remediation":"Enable IAM Access Analyzer in all regions via the IAM console.",
     "reference":"CIS AWS v1.5 — 1.21"},

    # ── S3 ───────────────────────────────────────────────────────────────────
    {"id":"2.1",  "section":"S3", "title":"S3 Block Public Access enabled at account level",
     "description":"Account-level Block Public Access prevents any bucket from being made public.",
     "remediation":"Enable all 4 Block Public Access settings in S3 → Block Public Access (account settings).",
     "reference":"CIS AWS v1.5 — 2.1.5"},
    {"id":"2.2",  "section":"S3", "title":"No S3 buckets with public ACLs",
     "description":"No S3 bucket should grant public access via ACL.",
     "remediation":"Remove AllUsers and AuthenticatedUsers grants from all bucket ACLs.",
     "reference":"CIS AWS v1.5 — 2.1.5"},
    {"id":"2.3",  "section":"S3", "title":"No S3 buckets with public bucket policies",
     "description":"No S3 bucket should have a policy with Principal: * without conditions.",
     "remediation":"Review and remove all public Principal: * statements from bucket policies.",
     "reference":"CIS AWS v1.5 — 2.1.5"},
    {"id":"2.4",  "section":"S3", "title":"S3 buckets have default encryption enabled",
     "description":"All S3 buckets should have default server-side encryption configured.",
     "remediation":"Enable SSE-S3 or SSE-KMS default encryption on all S3 buckets.",
     "reference":"CIS AWS v1.5 — 2.1.1"},
    {"id":"2.5",  "section":"S3", "title":"S3 buckets deny HTTP access (enforce HTTPS)",
     "description":"Bucket policies should deny requests over unencrypted HTTP connections.",
     "remediation":"Add a deny policy statement with Condition aws:SecureTransport: false to all buckets.",
     "reference":"CIS AWS v1.5 — 2.1.2"},
    {"id":"2.6",  "section":"S3", "title":"S3 bucket access logging enabled",
     "description":"Server access logging should be enabled for all S3 buckets.",
     "remediation":"Enable server access logging and send logs to a dedicated logging bucket.",
     "reference":"CIS AWS v1.5 — 2.1.3"},
    {"id":"2.7",  "section":"S3", "title":"S3 buckets have versioning enabled",
     "description":"Versioning protects against accidental deletion and ransomware.",
     "remediation":"Enable versioning on all S3 buckets containing important data.",
     "reference":"CIS AWS v1.5 — 2.1.x"},
    {"id":"2.8",  "section":"S3", "title":"S3 buckets have lifecycle policies",
     "description":"Lifecycle policies enforce data retention and reduce attack surface.",
     "remediation":"Create lifecycle rules to transition and expire objects per your data retention policy.",
     "reference":"CIS AWS v1.5 — 2.1.x"},

    # ── Logging ───────────────────────────────────────────────────────────────
    {"id":"3.1",  "section":"Logging", "title":"CloudTrail enabled in all regions",
     "description":"A multi-region CloudTrail trail must be enabled to log all API activity.",
     "remediation":"Create a multi-region CloudTrail trail covering all AWS regions.",
     "reference":"CIS AWS v1.5 — 3.1"},
    {"id":"3.2",  "section":"Logging", "title":"CloudTrail log file validation enabled",
     "description":"Log file validation ensures trail logs have not been tampered with.",
     "remediation":"Enable log file integrity validation on all CloudTrail trails.",
     "reference":"CIS AWS v1.5 — 3.2"},
    {"id":"3.3",  "section":"Logging", "title":"CloudTrail S3 bucket not publicly accessible",
     "description":"The S3 bucket storing CloudTrail logs must not be publicly accessible.",
     "remediation":"Enable Block Public Access on the CloudTrail S3 bucket.",
     "reference":"CIS AWS v1.5 — 3.3"},
    {"id":"3.4",  "section":"Logging", "title":"CloudTrail logs encrypted with KMS",
     "description":"CloudTrail log files should be encrypted using KMS Customer Managed Keys.",
     "remediation":"Configure CloudTrail to use a KMS CMK for log encryption.",
     "reference":"CIS AWS v1.5 — 3.7"},
    {"id":"3.5",  "section":"Logging", "title":"AWS Config enabled in all regions",
     "description":"AWS Config records resource configuration changes for compliance monitoring.",
     "remediation":"Enable AWS Config in all regions with all resource types recorded.",
     "reference":"CIS AWS v1.5 — 3.5"},
    {"id":"3.6",  "section":"Logging", "title":"CloudTrail S3 bucket has access logging enabled",
     "description":"Access logging on the CloudTrail S3 bucket records all access to audit logs.",
     "remediation":"Enable S3 server access logging on the bucket storing CloudTrail logs.",
     "reference":"CIS AWS v1.5 — 3.6"},
    {"id":"3.7",  "section":"Logging", "title":"VPC Flow Logs enabled in all VPCs",
     "description":"VPC Flow Logs capture network traffic metadata for threat detection.",
     "remediation":"Enable VPC Flow Logs for all VPCs and send to CloudWatch Logs or S3.",
     "reference":"CIS AWS v1.5 — 3.9"},
    {"id":"3.8",  "section":"Logging", "title":"CloudTrail integrated with CloudWatch Logs",
     "description":"CloudTrail trails should stream logs to CloudWatch for real-time alerting.",
     "remediation":"Configure CloudTrail to send logs to a CloudWatch Logs log group.",
     "reference":"CIS AWS v1.5 — 3.4"},

    # ── Monitoring ────────────────────────────────────────────────────────────
    {"id":"4.1",  "section":"Monitoring", "title":"Alarm for unauthorized API calls",
     "description":"A CloudWatch alarm must exist for unauthorized AWS API call attempts.",
     "remediation":"Create a metric filter and alarm for ErrorCode = *UnauthorizedOperation*.",
     "reference":"CIS AWS v1.5 — 3.1"},
    {"id":"4.2",  "section":"Monitoring", "title":"Alarm for root account usage",
     "description":"Any root account activity must trigger an immediate alert.",
     "remediation":"Create a metric filter and alarm for userIdentity.type = Root.",
     "reference":"CIS AWS v1.5 — 3.3"},
    {"id":"4.3",  "section":"Monitoring", "title":"Alarm for IAM policy changes",
     "description":"Changes to IAM policies must trigger an alert for immediate review.",
     "remediation":"Create metric filter for IAM CreatePolicy, DeletePolicy, AttachRolePolicy events.",
     "reference":"CIS AWS v1.5 — 3.4"},
    {"id":"4.4",  "section":"Monitoring", "title":"Alarm for CloudTrail configuration changes",
     "description":"Any changes to CloudTrail configuration must be alerted immediately.",
     "remediation":"Create metric filter for CloudTrail StopLogging, DeleteTrail, UpdateTrail events.",
     "reference":"CIS AWS v1.5 — 3.5"},
    {"id":"4.5",  "section":"Monitoring", "title":"Alarm for S3 bucket policy changes",
     "description":"Changes to S3 bucket policies must trigger an alert.",
     "remediation":"Create metric filter for S3 PutBucketPolicy, DeleteBucketPolicy events.",
     "reference":"CIS AWS v1.5 — 3.8"},
    {"id":"4.6",  "section":"Monitoring", "title":"Alarm for security group changes",
     "description":"Changes to EC2 security group rules must trigger an alert.",
     "remediation":"Create metric filter for AuthorizeSecurityGroup*, RevokeSecurityGroup* events.",
     "reference":"CIS AWS v1.5 — 3.10"},
    {"id":"4.7",  "section":"Monitoring", "title":"Alarm for NACL changes",
     "description":"Changes to Network ACLs must trigger an alert.",
     "remediation":"Create metric filter for CreateNetworkAcl, DeleteNetworkAcl, ReplaceNetworkAclEntry events.",
     "reference":"CIS AWS v1.5 — 3.11"},
    {"id":"4.8",  "section":"Monitoring", "title":"Alarm for network gateway changes",
     "description":"Changes to internet or VPN gateways must trigger an alert.",
     "remediation":"Create metric filter for CreateCustomerGateway, DeleteCustomerGateway, AttachInternetGateway events.",
     "reference":"CIS AWS v1.5 — 3.12"},
    {"id":"4.9",  "section":"Monitoring", "title":"Alarm for VPC changes",
     "description":"Changes to VPC configuration must trigger an alert.",
     "remediation":"Create metric filter for CreateVpc, DeleteVpc, ModifyVpcAttribute events.",
     "reference":"CIS AWS v1.5 — 3.14"},
    {"id":"4.10", "section":"Monitoring", "title":"AWS GuardDuty enabled",
     "description":"GuardDuty provides ML-based threat detection for the AWS account.",
     "remediation":"Enable GuardDuty in all regions via the AWS console or CLI.",
     "reference":"CIS AWS v1.5 — 3.x"},
    {"id":"4.11", "section":"Monitoring", "title":"AWS Security Hub enabled",
     "description":"Security Hub provides centralised compliance and security findings.",
     "remediation":"Enable Security Hub with CIS AWS Foundations Benchmark standard.",
     "reference":"CIS AWS v1.5 — 3.x"},
    {"id":"4.12", "section":"Monitoring", "title":"Alarm for console sign-in without MFA",
     "description":"Console logins without MFA should trigger an immediate alert.",
     "remediation":"Create metric filter for ConsoleLogin events where MFA = No.",
     "reference":"CIS AWS v1.5 — 3.2"},

    # ── Networking ────────────────────────────────────────────────────────────
    {"id":"5.1",  "section":"Networking", "title":"No security groups allow SSH from 0.0.0.0/0",
     "description":"SSH (port 22) must not be open to the entire internet.",
     "remediation":"Restrict SSH to specific IP ranges or use AWS Systems Manager Session Manager.",
     "reference":"CIS AWS v1.5 — 5.2"},
    {"id":"5.2",  "section":"Networking", "title":"No security groups allow RDP from 0.0.0.0/0",
     "description":"RDP (port 3389) must not be open to the entire internet.",
     "remediation":"Close RDP port. Use AWS Systems Manager Fleet Manager for Windows access.",
     "reference":"CIS AWS v1.5 — 5.3"},
    {"id":"5.3",  "section":"Networking", "title":"No security groups allow all traffic inbound",
     "description":"No security group should have an inbound rule allowing all traffic (0.0.0.0/0 on all ports).",
     "remediation":"Remove all-traffic inbound rules. Define specific port and source allowlists.",
     "reference":"CIS AWS v1.5 — 5.x"},
    {"id":"5.4",  "section":"Networking", "title":"Default VPC security group blocks all traffic",
     "description":"The default VPC security group should not allow any inbound or outbound traffic.",
     "remediation":"Remove all inbound and outbound rules from the default VPC security group.",
     "reference":"CIS AWS v1.5 — 5.4"},
    {"id":"5.5",  "section":"Networking", "title":"No unused default VPC in any region",
     "description":"Default VPCs should not be used or should be deleted if unused.",
     "remediation":"Delete unused default VPCs in each region. Use purpose-built VPCs instead.",
     "reference":"CIS AWS v1.5 — 5.1"},
    {"id":"5.6",  "section":"Networking", "title":"VPC peering does not allow overly permissive routing",
     "description":"VPC peering connections should not allow access to entire CIDR ranges unnecessarily.",
     "remediation":"Review VPC peering route tables. Restrict routes to only required subnets.",
     "reference":"CIS AWS v1.5 — 5.5"},
]

CONTROL_MAP = {c["id"]: c for c in CONTROLS}

# ─────────────────────────────────────────────────────────────────────────────
# TERMINAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def clr(t, c): return f"\033[{c}m{t}\033[0m"
def green(t):  return clr(t, "32")
def red(t):    return clr(t, "31")
def yellow(t): return clr(t, "33")
def bold(t):   return clr(t, "1")
def dim(t):    return clr(t, "2")

def banner():
    print("\n")
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║     AWS CIS BENCHMARK CHECKER v1.5                     ║"))
    print(bold("║     Cloud Security Consultant Tool                     ║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))
    print(dim(f"  {len(CONTROLS)} controls · 5 sections · IAM · S3 · Logging · Monitoring · Networking\n"))

def sep(title=""):
    print("\n" + "─" * 60)
    if title:
        print(f"  {bold(title)}")
        print("─" * 60)

def ask(label, default=None, secret=False):
    hint = f" [{default}]" if default else ""
    while True:
        if secret:
            import getpass
            val = getpass.getpass(f"  {label}{hint}: ").strip()
        else:
            val = input(f"  {label}{hint}: ").strip()
        if val:      return val
        if default:  return default
        print(red("  ⚠  Required."))

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — COLLECT INPUTS
# ─────────────────────────────────────────────────────────────────────────────
def collect_inputs():
    banner()
    sep("STEP 1 of 3 — YOUR CONSULTANT DETAILS")
    consultant = {
        "name":  ask("Your full name",       default="Your Name"),
        "title": ask("Your title",            default="Cloud Security Consultant"),
        "email": ask("Your email",            default="hello@yoursite.com"),
        "certs": ask("Your certifications",   default="AWS SAA Certified | ISO 27001 | NIST | GDPR"),
    }
    sep("STEP 2 of 3 — CLIENT DETAILS")
    client = {
        "name":     ask("Client company name"),
        "industry": ask("Client industry",    default="SaaS"),
        "contact":  ask("Client contact",     default="CTO"),
    }
    sep("STEP 3 of 3 — AWS CREDENTIALS")
    print(dim("  Read-only access required. Scanner never modifies resources.\n"))
    creds = {
        "access_key":    ask("AWS Access Key ID",     secret=True),
        "secret_key":    ask("AWS Secret Access Key", secret=True),
        "session_token": ask("Session Token (optional — Enter to skip)", default=""),
        "region":        ask("Default region",        default="us-east-1"),
        "account_id":    ask("AWS Account ID"),
    }
    safe = client["name"].lower().replace(" ","_").replace(".","").replace(",","")
    out  = ask("Output PDF filename", default=f"cis_report_{safe}_{date.today().strftime('%Y%m%d')}.pdf")
    if not out.endswith(".pdf"): out += ".pdf"
    return consultant, client, creds, out

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — AWS CHECKS
# ─────────────────────────────────────────────────────────────────────────────
def connect(creds):
    try:
        import boto3
        kw = dict(aws_access_key_id=creds["access_key"],
                  aws_secret_access_key=creds["secret_key"],
                  region_name=creds["region"])
        if creds["session_token"]:
            kw["aws_session_token"] = creds["session_token"]
        return boto3.Session(**kw)
    except Exception as e:
        print(red(f"  ✗ Connection failed: {e}")); sys.exit(1)

def safe(fn, *a, **kw):
    try:    return fn(*a, **kw), None
    except Exception as e: return None, str(e)

def result(status, detail=""):
    return {"status": status, "detail": detail}

def run_checks(session):
    sep("RUNNING CIS CHECKS")
    results = {}
    iam = session.client("iam")
    s3  = session.client("s3")
    ct  = session.client("cloudtrail")
    ec2 = session.client("ec2")

    # helper — get all regions
    ec2_regions = session.client("ec2", region_name="us-east-1")
    reg_resp, _ = safe(ec2_regions.describe_regions, Filters=[{"Name":"opt-in-status","Values":["opt-in-not-required","opted-in"]}])
    all_regions = [r["RegionName"] for r in (reg_resp or {}).get("Regions",[])] or [session.region_name]

    total = len(CONTROLS)
    for i, ctrl in enumerate(CONTROLS, 1):
        cid = ctrl["id"]
        print(f"  [{i:>2}/{total}]  {cid:<6} {ctrl['title'][:55]}", end="\r")

        # ── IAM ──────────────────────────────────────────────────────────────
        if cid == "1.1":
            acct, err = safe(iam.get_account_summary)
            if err: results[cid] = result("ERROR", err)
            else:
                mfa = acct["SummaryMap"].get("AccountMFAEnabled", 0)
                results[cid] = result("PASS" if mfa else "FAIL",
                    "Root account MFA is enabled." if mfa else "Root account MFA is NOT enabled.")

        elif cid == "1.2":
            keys, err = safe(iam.list_access_keys, UserName="root" if False else None)
            # Use credential report instead
            try:
                iam.generate_credential_report()
            except: pass
            rep, err = safe(iam.get_credential_report)
            if err: results[cid] = result("ERROR", err)
            else:
                import csv, io
                reader = csv.DictReader(io.StringIO(rep["Content"].decode()))
                for row in reader:
                    if row.get("user") == "<root_account>":
                        k1 = row.get("access_key_1_active","false")
                        k2 = row.get("access_key_2_active","false")
                        has_keys = k1.lower() == "true" or k2.lower() == "true"
                        results[cid] = result(
                            "FAIL" if has_keys else "PASS",
                            "Root account has active access keys." if has_keys else "No active root access keys found.")
                        break
                else:
                    results[cid] = result("ERROR", "Root account row not found in credential report.")

        elif cid == "1.3":
            users, err = safe(iam.list_users)
            if err: results[cid] = result("ERROR", err)
            else:
                no_mfa = []
                for u in users.get("Users",[]):
                    lp, _ = safe(iam.list_login_profiles, UserName=u["UserName"])
                    if not lp: continue
                    mfas, _ = safe(iam.list_mfa_devices, UserName=u["UserName"])
                    if not (mfas or {}).get("MFADevices"):
                        no_mfa.append(u["UserName"])
                results[cid] = result(
                    "FAIL" if no_mfa else "PASS",
                    f"Users without MFA: {', '.join(no_mfa)}" if no_mfa else "All console users have MFA enabled.")

        elif cid == "1.4":
            # Same as 1.2 — check credential report
            rep, err = safe(iam.get_credential_report)
            if err:
                try: iam.generate_credential_report()
                except: pass
                rep, err = safe(iam.get_credential_report)
            if err: results[cid] = result("ERROR", err)
            else:
                import csv, io
                reader = csv.DictReader(io.StringIO(rep["Content"].decode()))
                for row in reader:
                    if row.get("user") == "<root_account>":
                        k1 = row.get("access_key_1_active","false")
                        k2 = row.get("access_key_2_active","false")
                        has = k1.lower()=="true" or k2.lower()=="true"
                        results[cid] = result("FAIL" if has else "PASS",
                            "Root has active access keys — DELETE IMMEDIATELY." if has
                            else "No root access keys exist.")
                        break
                else:
                    results[cid] = result("ERROR", "Could not find root in credential report.")

        elif cid in ("1.5","1.6","1.7","1.8","1.9","1.10","1.11"):
            pol, err = safe(iam.get_account_password_policy)
            if err:
                results[cid] = result("FAIL", "No IAM password policy configured.")
            else:
                pp = pol.get("PasswordPolicy", {})
                checks = {
                    "1.5":  (pp.get("MinimumPasswordLength",0) >= 14,
                             f"Min length: {pp.get('MinimumPasswordLength',0)} (required: 14)"),
                    "1.6":  (pp.get("RequireUppercaseCharacters", False),
                             "Uppercase required." if pp.get("RequireUppercaseCharacters") else "Uppercase NOT required."),
                    "1.7":  (pp.get("RequireLowercaseCharacters", False),
                             "Lowercase required." if pp.get("RequireLowercaseCharacters") else "Lowercase NOT required."),
                    "1.8":  (pp.get("RequireNumbers", False),
                             "Numbers required." if pp.get("RequireNumbers") else "Numbers NOT required."),
                    "1.9":  (pp.get("RequireSymbols", False),
                             "Symbols required." if pp.get("RequireSymbols") else "Symbols NOT required."),
                    "1.10": (pp.get("PasswordReusePrevention",0) >= 24,
                             f"Reuse prevention: {pp.get('PasswordReusePrevention',0)} (required: 24)"),
                    "1.11": (pp.get("MaxPasswordAge",0) <= 90 and pp.get("MaxPasswordAge",0) > 0,
                             f"Max age: {pp.get('MaxPasswordAge','Not set')} days (required: ≤90)"),
                }
                passed, detail = checks[cid]
                results[cid] = result("PASS" if passed else "FAIL", detail)

        elif cid == "1.12":
            rep, err = safe(iam.get_credential_report)
            if err:
                try: iam.generate_credential_report()
                except: pass
                rep, err = safe(iam.get_credential_report)
            if err: results[cid] = result("ERROR", err)
            else:
                import csv, io
                from datetime import timezone, timedelta
                stale = []
                reader = csv.DictReader(io.StringIO(rep["Content"].decode()))
                cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                for row in reader:
                    if row.get("user") == "<root_account>": continue
                    for col in ["password_last_used","access_key_1_last_used_date","access_key_2_last_used_date"]:
                        val = row.get(col,"")
                        if val and val not in ("N/A","no_information","not_supported"):
                            try:
                                last = datetime.fromisoformat(val.replace("Z","+00:00"))
                                if last < cutoff and row.get("user") not in stale:
                                    stale.append(row.get("user","?"))
                            except: pass
                results[cid] = result(
                    "FAIL" if stale else "PASS",
                    f"Stale credentials (90+ days unused): {', '.join(stale[:5])}{'...' if len(stale)>5 else ''}" if stale
                    else "No credentials unused for 90+ days.")

        elif cid == "1.13":
            users, err = safe(iam.list_users)
            if err: results[cid] = result("ERROR", err)
            else:
                admins = []
                for u in users.get("Users",[]):
                    pols, _ = safe(iam.list_attached_user_policies, UserName=u["UserName"])
                    for p in (pols or {}).get("AttachedPolicies",[]):
                        if p.get("PolicyName") == "AdministratorAccess":
                            admins.append(u["UserName"])
                results[cid] = result(
                    "FAIL" if admins else "PASS",
                    f"Users with AdministratorAccess: {', '.join(admins)}" if admins
                    else "No IAM users have direct AdministratorAccess.")

        elif cid == "1.14":
            aa, err = safe(iam.list_analyzers if hasattr(iam,"list_analyzers") else lambda: None)
            # Use accessanalyzer client
            try:
                aa_client = session.client("accessanalyzer", region_name=session.region_name)
                analyzers, err = safe(aa_client.list_analyzers)
                active = [a for a in (analyzers or {}).get("analyzers",[]) if a.get("status")=="ACTIVE"]
                results[cid] = result("PASS" if active else "FAIL",
                    f"{len(active)} active analyzer(s) found." if active else "No active IAM Access Analyzers found.")
            except Exception as e:
                results[cid] = result("ERROR", str(e))

        # ── S3 ───────────────────────────────────────────────────────────────
        elif cid == "2.1":
            bpa, err = safe(s3.get_public_access_block)
            if err: results[cid] = result("FAIL", "No account-level Block Public Access configured.")
            else:
                cfg = bpa.get("PublicAccessBlockConfiguration",{})
                all_on = all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                              cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")])
                results[cid] = result("PASS" if all_on else "FAIL",
                    "All 4 account-level BPA settings enabled." if all_on
                    else f"BPA: BlockAcls={cfg.get('BlockPublicAcls',False)} IgnoreAcls={cfg.get('IgnorePublicAcls',False)} BlockPolicy={cfg.get('BlockPublicPolicy',False)} Restrict={cfg.get('RestrictPublicBuckets',False)}")

        elif cid in ("2.2","2.3","2.4","2.5","2.6","2.7","2.8"):
            buckets_resp, err = safe(s3.list_buckets)
            if err: results[cid] = result("ERROR", err); continue
            bnames = [b["Name"] for b in buckets_resp.get("Buckets",[])]
            fail_buckets = []
            for bn in bnames:
                if cid == "2.2":
                    acl, e = safe(s3.get_bucket_acl, Bucket=bn)
                    PUBLIC = ["http://acs.amazonaws.com/groups/global/AllUsers",
                              "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
                    if acl and any(g.get("Grantee",{}).get("URI") in PUBLIC for g in acl.get("Grants",[])):
                        fail_buckets.append(bn)
                elif cid == "2.3":
                    pol, e = safe(s3.get_bucket_policy, Bucket=bn)
                    if pol:
                        try:
                            doc = json.loads(pol["Policy"])
                            for stmt in doc.get("Statement",[]):
                                pr = stmt.get("Principal","")
                                if stmt.get("Effect")=="Allow" and (pr=="*" or pr=={"AWS":"*"}) and not stmt.get("Condition"):
                                    fail_buckets.append(bn); break
                        except: pass
                elif cid == "2.4":
                    enc, e = safe(s3.get_bucket_encryption, Bucket=bn)
                    if e or not (enc or {}).get("ServerSideEncryptionConfiguration",{}).get("Rules"):
                        fail_buckets.append(bn)
                elif cid == "2.5":
                    pol, e = safe(s3.get_bucket_policy, Bucket=bn)
                    found = False
                    if pol:
                        try:
                            doc = json.loads(pol["Policy"])
                            for stmt in doc.get("Statement",[]):
                                if stmt.get("Effect")=="Deny" and stmt.get("Condition",{}).get("Bool",{}).get("aws:SecureTransport") in ["false",False]:
                                    found = True; break
                        except: pass
                    if not found: fail_buckets.append(bn)
                elif cid == "2.6":
                    log, e = safe(s3.get_bucket_logging, Bucket=bn)
                    if not (log or {}).get("LoggingEnabled"): fail_buckets.append(bn)
                elif cid == "2.7":
                    ver, e = safe(s3.get_bucket_versioning, Bucket=bn)
                    if (ver or {}).get("Status") != "Enabled": fail_buckets.append(bn)
                elif cid == "2.8":
                    lc, e = safe(s3.get_bucket_lifecycle_configuration, Bucket=bn)
                    if e or not any(r.get("Status")=="Enabled" for r in (lc or {}).get("Rules",[])):
                        fail_buckets.append(bn)

            if fail_buckets:
                results[cid] = result("FAIL",
                    f"Non-compliant bucket(s) [{len(fail_buckets)}/{len(bnames)}]: {', '.join(fail_buckets[:4])}{'...' if len(fail_buckets)>4 else ''}")
            else:
                results[cid] = result("PASS", f"All {len(bnames)} bucket(s) passed this check.")

        # ── Logging ───────────────────────────────────────────────────────────
        elif cid == "3.1":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                multi = [t for t in trails.get("trailList",[]) if t.get("IsMultiRegionTrail") and t.get("HomeRegion")==session.region_name]
                if multi:
                    # Check if enabled
                    status, _ = safe(ct.get_trail_status, Name=multi[0]["TrailARN"])
                    enabled = (status or {}).get("IsLogging", False)
                    results[cid] = result("PASS" if enabled else "FAIL",
                        f"Multi-region trail '{multi[0]['Name']}' is {'active' if enabled else 'DISABLED'}.")
                else:
                    results[cid] = result("FAIL", "No multi-region CloudTrail trail found.")

        elif cid == "3.2":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                tlist = trails.get("trailList",[])
                no_val = [t["Name"] for t in tlist if not t.get("LogFileValidationEnabled")]
                results[cid] = result("FAIL" if no_val else "PASS",
                    f"Trails without validation: {', '.join(no_val)}" if no_val
                    else "All trails have log file validation enabled.")

        elif cid == "3.3":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                exposed = []
                for t in trails.get("trailList",[]):
                    bn = t.get("S3BucketName","")
                    if not bn: continue
                    bpa, _ = safe(s3.get_bucket_public_access_block, Bucket=bn)
                    cfg = (bpa or {}).get("PublicAccessBlockConfiguration",{})
                    if not all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                                cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]):
                        exposed.append(bn)
                results[cid] = result("FAIL" if exposed else "PASS",
                    f"CloudTrail bucket(s) not fully protected: {', '.join(exposed)}" if exposed
                    else "CloudTrail S3 bucket(s) have Block Public Access enabled.")

        elif cid == "3.4":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                no_kms = [t["Name"] for t in trails.get("trailList",[]) if not t.get("KMSKeyId")]
                results[cid] = result("FAIL" if no_kms else "PASS",
                    f"Trails without KMS encryption: {', '.join(no_kms)}" if no_kms
                    else "All trails encrypted with KMS.")

        elif cid == "3.5":
            try:
                cfg_client = session.client("config")
                recorders, err = safe(cfg_client.describe_configuration_recorders)
                if err or not recorders.get("ConfigurationRecorders"):
                    results[cid] = result("FAIL", "AWS Config not configured in this region.")
                else:
                    status_resp, _ = safe(cfg_client.describe_configuration_recorder_status)
                    recording = any(s.get("recording") for s in (status_resp or {}).get("ConfigurationRecordersStatus",[]))
                    results[cid] = result("PASS" if recording else "FAIL",
                        "AWS Config is recording." if recording else "AWS Config recorder exists but is not recording.")
            except Exception as e:
                results[cid] = result("ERROR", str(e))

        elif cid == "3.6":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                no_log = []
                for t in trails.get("trailList",[]):
                    bn = t.get("S3BucketName","")
                    if not bn: continue
                    log, _ = safe(s3.get_bucket_logging, Bucket=bn)
                    if not (log or {}).get("LoggingEnabled"): no_log.append(bn)
                results[cid] = result("FAIL" if no_log else "PASS",
                    f"CloudTrail buckets without access logging: {', '.join(no_log)}" if no_log
                    else "CloudTrail S3 bucket(s) have access logging enabled.")

        elif cid == "3.7":
            no_flow = []
            for region in all_regions[:5]:  # check up to 5 regions for speed
                try:
                    ec2r = session.client("ec2", region_name=region)
                    vpcs, _ = safe(ec2r.describe_vpcs)
                    for vpc in (vpcs or {}).get("Vpcs",[]):
                        vid = vpc["VpcId"]
                        fl, _ = safe(ec2r.describe_flow_logs,
                                     Filters=[{"Name":"resource-id","Values":[vid]}])
                        if not (fl or {}).get("FlowLogs"):
                            no_flow.append(f"{vid} ({region})")
                except: pass
            results[cid] = result("FAIL" if no_flow else "PASS",
                f"VPCs without flow logs: {', '.join(no_flow[:4])}{'...' if len(no_flow)>4 else ''}" if no_flow
                else "All VPCs have flow logs enabled.")

        elif cid == "3.8":
            trails, err = safe(ct.describe_trails, includeShadowTrails=False)
            if err: results[cid] = result("ERROR", err)
            else:
                no_cw = [t["Name"] for t in trails.get("trailList",[]) if not t.get("CloudWatchLogsLogGroupArn")]
                results[cid] = result("FAIL" if no_cw else "PASS",
                    f"Trails not sending to CloudWatch: {', '.join(no_cw)}" if no_cw
                    else "All trails integrated with CloudWatch Logs.")

        # ── Monitoring ────────────────────────────────────────────────────────
        elif cid in ("4.1","4.2","4.3","4.4","4.5","4.6","4.7","4.8","4.9","4.12"):
            # Check for CloudWatch metric filters + alarms
            PATTERNS = {
                "4.1":  "UnauthorizedOperation",
                "4.2":  'userIdentity.type = "Root"',
                "4.3":  "DeleteGroupPolicy",
                "4.4":  "DeleteTrail",
                "4.5":  "PutBucketPolicy",
                "4.6":  "AuthorizeSecurityGroupIngress",
                "4.7":  "CreateNetworkAcl",
                "4.8":  "CreateCustomerGateway",
                "4.9":  "CreateVpc",
                "4.12": "ConsoleLogin",
            }
            try:
                cw = session.client("logs")
                groups, _ = safe(cw.describe_log_groups)
                filters_found = False
                for grp in (groups or {}).get("logGroups",[]):
                    filters, _ = safe(cw.describe_metric_filters, logGroupName=grp["logGroupName"])
                    for f in (filters or {}).get("metricFilters",[]):
                        if PATTERNS[cid].split()[0].lower() in f.get("filterPattern","").lower():
                            filters_found = True; break
                    if filters_found: break
                results[cid] = result("PASS" if filters_found else "FAIL",
                    f"Metric filter for '{PATTERNS[cid][:40]}' found." if filters_found
                    else f"No CloudWatch metric filter found for '{PATTERNS[cid][:40]}'.")
            except Exception as e:
                results[cid] = result("ERROR", str(e))

        elif cid == "4.10":
            try:
                gd = session.client("guardduty")
                detectors, err = safe(gd.list_detectors)
                if err: results[cid] = result("ERROR", err)
                else:
                    dids = detectors.get("DetectorIds",[])
                    if dids:
                        det, _ = safe(gd.get_detector, DetectorId=dids[0])
                        enabled = (det or {}).get("Status") == "ENABLED"
                        results[cid] = result("PASS" if enabled else "FAIL",
                            "GuardDuty enabled and active." if enabled else "GuardDuty detector exists but is DISABLED.")
                    else:
                        results[cid] = result("FAIL", "GuardDuty is not enabled in this region.")
            except Exception as e:
                results[cid] = result("ERROR", str(e))

        elif cid == "4.11":
            try:
                sh = session.client("securityhub")
                hub, err = safe(sh.describe_hub)
                if err:
                    results[cid] = result("FAIL", "AWS Security Hub is not enabled.")
                else:
                    results[cid] = result("PASS", f"Security Hub enabled: {hub.get('HubArn','')[-40:]}")
            except Exception as e:
                results[cid] = result("FAIL", "Security Hub not enabled or not accessible.")

        # ── Networking ────────────────────────────────────────────────────────
        elif cid in ("5.1","5.2","5.3"):
            PORT_MAP = {"5.1": 22, "5.2": 3389, "5.3": -1}
            port = PORT_MAP[cid]
            bad_sgs = []
            for region in all_regions[:5]:
                try:
                    ec2r = session.client("ec2", region_name=region)
                    sgs, _ = safe(ec2r.describe_security_groups)
                    for sg in (sgs or {}).get("SecurityGroups",[]):
                        for rule in sg.get("IpPermissions",[]):
                            from_p = rule.get("FromPort", 0)
                            to_p   = rule.get("ToPort", 65535)
                            proto  = rule.get("IpProtocol","-1")
                            cidrs  = [r.get("CidrIp","") for r in rule.get("IpRanges",[])]
                            cidrs += [r.get("CidrIpv6","") for r in rule.get("Ipv6Ranges",[])]
                            is_open = "0.0.0.0/0" in cidrs or "::/0" in cidrs
                            if not is_open: continue
                            if port == -1 and proto == "-1":
                                bad_sgs.append(f"{sg['GroupId']} ({region})")
                                break
                            elif port != -1 and proto in ("-1","tcp") and from_p <= port <= to_p:
                                bad_sgs.append(f"{sg['GroupId']} ({region})")
                                break
                except: pass
            results[cid] = result("FAIL" if bad_sgs else "PASS",
                f"Security groups open to internet: {', '.join(bad_sgs[:4])}{'...' if len(bad_sgs)>4 else ''}" if bad_sgs
                else "No security groups with this exposure found.")

        elif cid == "5.4":
            bad = []
            for region in all_regions[:5]:
                try:
                    ec2r = session.client("ec2", region_name=region)
                    vpcs, _ = safe(ec2r.describe_vpcs, Filters=[{"Name":"isDefault","Values":["true"]}])
                    for vpc in (vpcs or {}).get("Vpcs",[]):
                        sgs, _ = safe(ec2r.describe_security_groups,
                                      Filters=[{"Name":"vpc-id","Values":[vpc["VpcId"]]},
                                               {"Name":"group-name","Values":["default"]}])
                        for sg in (sgs or {}).get("SecurityGroups",[]):
                            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                                bad.append(f"{vpc['VpcId']} ({region})")
                except: pass
            results[cid] = result("FAIL" if bad else "PASS",
                f"Default SGs with rules: {', '.join(bad[:4])}" if bad
                else "Default VPC security groups have no rules.")

        elif cid == "5.5":
            used = []
            for region in all_regions[:5]:
                try:
                    ec2r = session.client("ec2", region_name=region)
                    vpcs, _ = safe(ec2r.describe_vpcs, Filters=[{"Name":"isDefault","Values":["true"]}])
                    for vpc in (vpcs or {}).get("Vpcs",[]):
                        # check if it has resources
                        subs, _ = safe(ec2r.describe_subnets, Filters=[{"Name":"vpc-id","Values":[vpc["VpcId"]]}])
                        if (subs or {}).get("Subnets"):
                            used.append(f"{vpc['VpcId']} ({region})")
                except: pass
            results[cid] = result("FAIL" if used else "PASS",
                f"Default VPCs with subnets (in use): {', '.join(used[:4])}" if used
                else "No default VPCs with active subnets found.")

        elif cid == "5.6":
            over_permissive = []
            for region in all_regions[:5]:
                try:
                    ec2r = session.client("ec2", region_name=region)
                    peerings, _ = safe(ec2r.describe_vpc_peering_connections,
                                       Filters=[{"Name":"status-code","Values":["active"]}])
                    for pc in (peerings or {}).get("VpcPeeringConnections",[]):
                        # Check route tables for overly broad routes
                        rts, _ = safe(ec2r.describe_route_tables)
                        for rt in (rts or {}).get("RouteTables",[]):
                            for route in rt.get("Routes",[]):
                                if (route.get("VpcPeeringConnectionId") == pc["VpcPeeringConnectionId"]
                                        and route.get("DestinationCidrBlock") in ("0.0.0.0/0","::/0")):
                                    over_permissive.append(pc["VpcPeeringConnectionId"])
                except: pass
            results[cid] = result("FAIL" if over_permissive else "PASS",
                f"Overly permissive peering routes: {', '.join(over_permissive)}" if over_permissive
                else "No overly permissive VPC peering routes found.")

        else:
            results[cid] = result("N/A", "Check not implemented in this version.")

    print(" " * 70, end="\r")
    passed = sum(1 for r in results.values() if r["status"]=="PASS")
    failed = sum(1 for r in results.values() if r["status"]=="FAIL")
    errors = sum(1 for r in results.values() if r["status"]=="ERROR")
    print(f"  {green('✓')} Completed {total} checks — "
          f"{green(str(passed))} passed · {red(str(failed))} failed · {yellow(str(errors))} errors\n")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# SCORE & SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def calc_score(results):
    total   = len(results)
    passed  = sum(1 for r in results.values() if r["status"]=="PASS")
    failed  = sum(1 for r in results.values() if r["status"]=="FAIL")
    errors  = sum(1 for r in results.values() if r["status"]=="ERROR")
    score   = round((passed / total) * 100) if total else 0
    rating  = ("COMPLIANT"          if score >= 90 else
               "MOSTLY COMPLIANT"   if score >= 75 else
               "PARTIALLY COMPLIANT"if score >= 50 else
               "NON-COMPLIANT")
    section_scores = {}
    for ctrl in CONTROLS:
        sec = ctrl["section"]
        r   = results.get(ctrl["id"], {})
        if sec not in section_scores:
            section_scores[sec] = {"pass":0,"fail":0,"error":0,"total":0}
        section_scores[sec]["total"] += 1
        st  = r.get("status","ERROR")
        if   st == "PASS":  section_scores[sec]["pass"]  += 1
        elif st == "FAIL":  section_scores[sec]["fail"]  += 1
        else:               section_scores[sec]["error"] += 1
    return {"total":total,"passed":passed,"failed":failed,"errors":errors,
            "score":score,"rating":rating,"sections":section_scores}

# ─────────────────────────────────────────────────────────────────────────────
# PDF CANVAS
# ─────────────────────────────────────────────────────────────────────────────
class CISCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self._meta  = kwargs.pop("meta", {})
        self._pages = []
        super().__init__(*args, **kwargs)

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for n, page in enumerate(self._pages, 1):
            self.__dict__.update(page)
            if n > 1: self._chrome(n, total)
            super().showPage()
        super().save()

    def _chrome(self, n, total):
        m = self._meta
        self.setFillColor(DARK)
        self.rect(0, H_PAGE-22*mm, W_PAGE, 22*mm, fill=1, stroke=0)
        self.setFillColor(PURPLE)
        self.rect(0, H_PAGE-22*mm, 4, 22*mm, fill=1, stroke=0)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(WHITE)
        self.drawString(14*mm, H_PAGE-13*mm, "CIS AWS FOUNDATIONS BENCHMARK v1.5 — COMPLIANCE REPORT")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#8B949E"))
        self.drawRightString(W_PAGE-14*mm, H_PAGE-13*mm, f"{m.get('client_name','')}  ·  CONFIDENTIAL")
        self.setFillColor(GRAY_LIGHT)
        self.rect(0, 0, W_PAGE, 12*mm, fill=1, stroke=0)
        self.setFillColor(PURPLE)
        self.rect(0, 0, W_PAGE, 1, fill=1, stroke=0)
        self.setFont("Helvetica", 7)
        self.setFillColor(GRAY)
        self.drawString(14*mm, 4*mm,
            f"Prepared by {m.get('consultant_name','')}  ·  {m.get('consultant_email','')}  ·  {m.get('consultant_certs','')}")
        self.drawRightString(W_PAGE-14*mm, 4*mm, f"Page {n} of {total}")

# ─────────────────────────────────────────────────────────────────────────────
# PDF HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def status_pill(status):
    color_map = {"PASS": GREEN, "FAIL": RED, "ERROR": ORANGE, "N/A": GRAY}
    c = color_map.get(status, GRAY)
    return Table([[Paragraph(status,
                  ParagraphStyle("sp", fontName="Helvetica-Bold", fontSize=7,
                                 textColor=c, alignment=TA_CENTER))]],
                 colWidths=[40],
                 style=TableStyle([
                     ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor(c.hexval()+"22")),
                     ("BOX",          (0,0),(-1,-1), 0.5, c),
                     ("TOPPADDING",   (0,0),(-1,-1), 3),
                     ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                 ]))

def section_header_row(section, fg, bg):
    return Table([[
        Paragraph(f"<b>Section {section}</b>",
                  ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE, leading=14)),
    ]], colWidths=[CONTENT_W],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), fg),
        ("LEFTPADDING",   (0,0),(-1,-1), 12),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE PDF
# ─────────────────────────────────────────────────────────────────────────────
def generate_pdf(output_path, consultant, client, creds, results, summary):
    scan_date = date.today().strftime("%B %d, %Y")
    scan_time = datetime.now().strftime("%H:%M UTC")
    meta = {"client_name": client["name"], "consultant_name": consultant["name"],
            "consultant_email": consultant["email"], "consultant_certs": consultant["certs"]}

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=28*mm, bottomMargin=18*mm,
                            title="CIS AWS Benchmark Compliance Report",
                            author=consultant["name"])
    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    sc = summary["score"]
    sc_clr = (RED if sc < 50 else ORANGE if sc < 75 else GREEN).hexval()

    cover = Table([[Table([
        [Paragraph("☁️ CIS AWS FOUNDATIONS", ST["cover_title"])],
        [Paragraph("BENCHMARK v1.5", ST["cover_title"])],
        [Paragraph("COMPLIANCE REPORT", ParagraphStyle("ct2", fontName="Helvetica-Bold",
                   fontSize=18, textColor=colors.HexColor("#9FE1CB"), leading=24))],
        [Spacer(1,8)],
        [Paragraph(f"Client: {client['name']}",           ST["cover_sub"])],
        [Paragraph(f"Industry: {client['industry']}",     ST["cover_meta"])],
        [Paragraph(f"AWS Account: {creds['account_id']}", ST["cover_meta"])],
        [Paragraph(f"Scan Date: {scan_date} {scan_time}", ST["cover_meta"])],
        [Spacer(1,10)],
        [HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363D"))],
        [Spacer(1,10)],
        [Paragraph(
            f'<font color="{sc_clr}" size="20"><b>{sc}/100</b></font>  '
            f'<font color="#8B949E" size="11">— {summary["rating"]}</font>',
            ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=20, textColor=WHITE, leading=26))],
        [Paragraph(
            f"Controls Passed: {summary['passed']} / {summary['total']}  |  "
            f"Failed: {summary['failed']}  |  Errors: {summary['errors']}",
            ST["cover_meta"])],
        [Spacer(1,20)],
        [HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363D"))],
        [Spacer(1,10)],
        [Paragraph(f"Consultant: {consultant['name']}",   ST["cover_sub"])],
        [Paragraph(consultant["title"],                   ST["cover_meta"])],
        [Paragraph(consultant["email"],                   ST["cover_meta"])],
        [Paragraph(consultant["certs"],                   ST["cover_meta"])],
        [Spacer(1,20)],
        [Paragraph("⚠  CONFIDENTIAL — For authorized recipients only", ST["cover_warn"])],
    ], colWidths=[CONTENT_W],
       style=TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),
                         ("LEFTPADDING",(0,0),(-1,-1),20),
                         ("RIGHTPADDING",(0,0),(-1,-1),20),
                         ("TOPPADDING",(0,0),(-1,-1),4),
                         ("BOTTOMPADDING",(0,0),(-1,-1),4)]))]],
    colWidths=[CONTENT_W],
    style=TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),
                      ("TOPPADDING",(0,0),(-1,-1),40),
                      ("BOTTOMPADDING",(0,0),(-1,-1),40),
                      ("LEFTPADDING",(0,0),(-1,-1),0),
                      ("RIGHTPADDING",(0,0),(-1,-1),0)]))
    story += [cover, PageBreak()]

    # ── TOC ───────────────────────────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=10))
    for item in ["1.  Executive Summary",
                 "2.  Compliance Score by Section",
                 "3.  IAM — Identity & Access Management",
                 "4.  S3 — Storage Security",
                 "5.  Logging — Audit Trail Controls",
                 "6.  Monitoring — Threat Detection",
                 "7.  Networking — Network Security",
                 "8.  Failed Controls — Detailed Findings",
                 "9.  Remediation Roadmap",
                 "10. Appendix — All Controls Reference"]:
        story.append(Paragraph(item, ST["toc"]))
    story.append(PageBreak())

    # ── 1. EXEC SUMMARY ───────────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=10))
    story.append(Paragraph(
        f"This CIS AWS Foundations Benchmark v1.5 compliance assessment was conducted on the "
        f"{client['name']} AWS environment on {scan_date}. "
        f"A total of {summary['total']} controls were evaluated across five domains: "
        f"IAM, S3, Logging, Monitoring, and Networking. "
        f"{summary['passed']} controls passed, {summary['failed']} failed, "
        f"and {summary['errors']} could not be evaluated due to permission or configuration errors. "
        f"The overall compliance score is {summary['score']}/100 — rated {summary['rating']}. "
        f"Failed controls represent gaps against industry-accepted security best practices "
        f"and may indicate violations of PCI-DSS, GDPR, ISO 27001, or SOC 2 requirements.",
        ST["body"]))
    story.append(Spacer(1, 12))

    # Score box
    sc_obj = RED if sc < 50 else ORANGE if sc < 75 else GREEN
    L = 68*mm; R = CONTENT_W - L

    left = Table([
        [Paragraph(f'<font size="40" color="{sc_obj.hexval()}"><b>{sc}</b></font>',
                   ParagraphStyle("s", alignment=TA_CENTER, leading=46, fontName="Helvetica-Bold"))],
        [Paragraph('<font size="9" color="#6E7681">out of 100</font>',
                   ParagraphStyle("s2", alignment=TA_CENTER, leading=12))],
        [Spacer(1,4)],
        [Paragraph('<font size="8"><b>COMPLIANCE SCORE</b></font>',
                   ParagraphStyle("s3", alignment=TA_CENTER, fontName="Helvetica-Bold",
                                  textColor=GRAY, leading=11))],
        [Paragraph(f'<font size="9" color="{sc_obj.hexval()}"><b>{summary["rating"]}</b></font>',
                   ParagraphStyle("s4", alignment=TA_CENTER, fontName="Helvetica-Bold", leading=13))],
    ], colWidths=[L],
       style=TableStyle([("BACKGROUND",(0,0),(-1,-1),GRAY_LIGHT),
                         ("ALIGN",(0,0),(-1,-1),"CENTER"),
                         ("TOPPADDING",(0,0),(0,0),18),
                         ("BOTTOMPADDING",(0,4),(-1,-1),18),
                         ("TOPPADDING",(0,1),(-1,-1),3),
                         ("BOTTOMPADDING",(0,0),(-1,3),3)]))

    IW = R - 32*mm
    breakdown = Table([
        [Paragraph("<b>Passed</b>",  ParagraphStyle("l", fontSize=9, fontName="Helvetica-Bold", textColor=GREEN)),
         Paragraph(f"<b>{summary['passed']}</b>",  ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=GREEN, alignment=TA_RIGHT))],
        [Paragraph("<b>Failed</b>",  ParagraphStyle("l", fontSize=9, fontName="Helvetica-Bold", textColor=RED)),
         Paragraph(f"<b>{summary['failed']}</b>",  ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=RED, alignment=TA_RIGHT))],
        [Paragraph("<b>Errors</b>",  ParagraphStyle("l", fontSize=9, fontName="Helvetica-Bold", textColor=ORANGE)),
         Paragraph(f"<b>{summary['errors']}</b>",  ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=ORANGE, alignment=TA_RIGHT))],
        [Paragraph("<b>Total</b>",   ParagraphStyle("l", fontSize=9, fontName="Helvetica-Bold", textColor=DARK)),
         Paragraph(f"<b>{summary['total']}</b>",   ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=DARK, alignment=TA_RIGHT))],
    ], colWidths=[IW, R-16*mm-IW],
       style=TableStyle([("LINEBELOW",(0,0),(-1,-2),0.5,colors.HexColor("#E6EDF3")),
                         ("TOPPADDING",(0,0),(-1,-1),5),
                         ("BOTTOMPADDING",(0,0),(-1,-1),5)]))

    right = Table([
        [Paragraph("<b>Control Results</b>",
                   ParagraphStyle("fb", fontSize=10, fontName="Helvetica-Bold", textColor=DARK, leading=14))],
        [breakdown],
    ], colWidths=[R],
       style=TableStyle([("BACKGROUND",(0,0),(-1,-1),WHITE),
                         ("LEFTPADDING",(0,0),(-1,-1),16),
                         ("RIGHTPADDING",(0,0),(-1,-1),16),
                         ("TOPPADDING",(0,0),(-1,-1),14),
                         ("BOTTOMPADDING",(0,0),(-1,-1),14),
                         ("BOX",(0,0),(-1,-1),0.5,colors.HexColor("#E6EDF3"))]))

    story.append(Table([[left, right]], colWidths=[L, R],
        style=TableStyle([("BOX",(0,0),(-1,-1),1,colors.HexColor("#E6EDF3")),
                          ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                          ("LEFTPADDING",(0,0),(-1,-1),0),
                          ("RIGHTPADDING",(0,0),(-1,-1),0),
                          ("TOPPADDING",(0,0),(-1,-1),0),
                          ("BOTTOMPADDING",(0,0),(-1,-1),0)])))
    story.append(PageBreak())

    # ── 2. SECTION SCORES ─────────────────────────────────────────────────────
    story.append(Paragraph("2. Compliance Score by Section", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=10))

    sec_rows = [[
        Paragraph("<b>Section</b>",    ST["th"]),
        Paragraph("<b>Passed</b>",     ST["th"]),
        Paragraph("<b>Failed</b>",     ST["th"]),
        Paragraph("<b>Errors</b>",     ST["th"]),
        Paragraph("<b>Total</b>",      ST["th"]),
        Paragraph("<b>Score</b>",      ST["th"]),
        Paragraph("<b>Status</b>",     ST["th"]),
    ]]
    for sec, data in summary["sections"].items():
        fg, bg = SECTION_COLORS.get(sec, (GRAY, GRAY_LIGHT))
        sec_score = round((data["pass"] / data["total"]) * 100) if data["total"] else 0
        status = "COMPLIANT" if sec_score >= 90 else "PARTIAL" if sec_score >= 50 else "NON-COMPLIANT"
        status_c = GREEN if sec_score >= 90 else ORANGE if sec_score >= 50 else RED
        sec_rows.append([
            Paragraph(f"<b>{sec}</b>", ParagraphStyle("sn", fontSize=9, fontName="Helvetica-Bold", textColor=fg, leading=12)),
            Paragraph(str(data["pass"]),  ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold", textColor=GREEN,  alignment=TA_CENTER, leading=12)),
            Paragraph(str(data["fail"]),  ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold", textColor=RED,    alignment=TA_CENTER, leading=12)),
            Paragraph(str(data["error"]), ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold", textColor=ORANGE, alignment=TA_CENTER, leading=12)),
            Paragraph(str(data["total"]), ParagraphStyle("v", fontSize=9, textColor=DARK,  alignment=TA_CENTER, leading=12)),
            Paragraph(f"<b>{sec_score}%</b>", ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold",
                      textColor=(GREEN if sec_score>=90 else ORANGE if sec_score>=50 else RED), alignment=TA_CENTER, leading=12)),
            Paragraph(status, ParagraphStyle("st", fontSize=8, fontName="Helvetica-Bold", textColor=status_c, alignment=TA_CENTER, leading=11)),
        ])

    CW = CONTENT_W
    story.append(Table(sec_rows,
        colWidths=[CW*0.22, CW*0.11, CW*0.11, CW*0.11, CW*0.10, CW*0.15, CW*0.20],
        style=TableStyle([("BACKGROUND",(0,0),(-1,0),DARK),
                          ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,GRAY_LIGHT]),
                          ("TOPPADDING",(0,0),(-1,-1),8),
                          ("BOTTOMPADDING",(0,0),(-1,-1),8),
                          ("LEFTPADDING",(0,0),(-1,-1),8),
                          ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#E6EDF3")),
                          ("VALIGN",(0,0),(-1,-1),"MIDDLE")])))
    story.append(PageBreak())

    # ── 3-7. PER-SECTION CONTROL TABLES ──────────────────────────────────────
    SECTION_NUMS = {"IAM":"3","S3":"4","Logging":"5","Monitoring":"6","Networking":"7"}
    SECTION_DESCS = {
        "IAM":        "Controls covering identity, access management, MFA, password policies, and credential hygiene.",
        "S3":         "Controls covering S3 bucket public access, encryption, logging, versioning, and lifecycle policies.",
        "Logging":    "Controls covering CloudTrail, AWS Config, VPC Flow Logs, and CloudWatch Logs integration.",
        "Monitoring": "Controls covering CloudWatch alarms, GuardDuty, Security Hub, and security event alerting.",
        "Networking": "Controls covering VPC security groups, NACLs, default VPCs, and network peering configurations.",
    }

    for section in ["IAM","S3","Logging","Monitoring","Networking"]:
        fg, bg = SECTION_COLORS[section]
        num    = SECTION_NUMS[section]
        ctrls  = [c for c in CONTROLS if c["section"] == section]

        story.append(Paragraph(f"{num}. {section} — Control Results", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=fg, spaceAfter=6))
        story.append(Paragraph(SECTION_DESCS[section], ST["body"]))
        story.append(Spacer(1, 10))

        rows = [[
            Paragraph("<b>Control</b>", ST["th"]),
            Paragraph("<b>Title</b>",   ST["th"]),
            Paragraph("<b>Result</b>",  ST["th"]),
            Paragraph("<b>Detail</b>",  ST["th"]),
        ]]
        for ctrl in ctrls:
            r  = results.get(ctrl["id"], {"status":"N/A","detail":""})
            st = r["status"]
            sc_c = (GREEN if st=="PASS" else RED if st=="FAIL" else ORANGE if st=="ERROR" else GRAY)
            rows.append([
                Paragraph(ctrl["id"], ST["td_mono"]),
                Paragraph(ctrl["title"], ST["td"]),
                Paragraph(f'<font color="{sc_c.hexval()}"><b>{st}</b></font>',
                          ParagraphStyle("sr", fontSize=8, fontName="Helvetica-Bold",
                                         textColor=sc_c, alignment=TA_CENTER, leading=11)),
                Paragraph(r.get("detail","")[:120], ST["small"]),
            ])

        story.append(Table(rows,
            colWidths=[CONTENT_W*0.10, CONTENT_W*0.33, CONTENT_W*0.12, CONTENT_W*0.45],
            style=TableStyle([("BACKGROUND",(0,0),(-1,0), fg),
                              ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, bg]),
                              ("TOPPADDING",(0,0),(-1,-1),6),
                              ("BOTTOMPADDING",(0,0),(-1,-1),6),
                              ("LEFTPADDING",(0,0),(-1,-1),7),
                              ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#E6EDF3")),
                              ("VALIGN",(0,0),(-1,-1),"TOP")])))
        story.append(PageBreak())

    # ── 8. FAILED CONTROLS ────────────────────────────────────────────────────
    story.append(Paragraph("8. Failed Controls — Detailed Findings", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=14))

    failed_ctrls = [c for c in CONTROLS if results.get(c["id"],{}).get("status") == "FAIL"]
    if not failed_ctrls:
        story.append(Paragraph("🎉 All controls passed. No failed controls to report.", ST["body"]))
    else:
        for ctrl in failed_ctrls:
            fg, bg = SECTION_COLORS.get(ctrl["section"], (GRAY, GRAY_LIGHT))
            r      = results.get(ctrl["id"], {})

            header = Table([[
                Paragraph(
                    f'<font color="{fg.hexval()}"><b>[{ctrl["id"]}]</b></font>  <b>{ctrl["title"]}</b>'
                    f'  <font color="#6E7681" size="8">— {ctrl["section"]}</font>',
                    ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=10, textColor=DARK, leading=13)),
                Table([[Paragraph("FAIL", ParagraphStyle("f", fontName="Helvetica-Bold", fontSize=7,
                                                          textColor=RED, alignment=TA_CENTER))]],
                      colWidths=[38],
                      style=TableStyle([("BACKGROUND",(0,0),(-1,-1),RED_LIGHT),
                                        ("BOX",(0,0),(-1,-1),0.5,RED),
                                        ("TOPPADDING",(0,0),(-1,-1),3),
                                        ("BOTTOMPADDING",(0,0),(-1,-1),3)])),
            ]], colWidths=[CONTENT_W-45, 42],
               style=TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(1,0),(-1,-1),"RIGHT")]))

            body_data = [
                [Paragraph("Found",        ST["label"]), Paragraph(r.get("detail",""), ST["body"])],
                [Paragraph("Description",  ST["label"]), Paragraph(ctrl["description"], ST["body"])],
                [Paragraph("Remediation",  ST["label"]), Paragraph(ctrl["remediation"],  ST["body"])],
                [Paragraph("Reference",    ST["label"]), Paragraph(ctrl["reference"],    ST["small"])],
            ]
            body = Table(body_data, colWidths=[26*mm, CONTENT_W-32*mm],
                style=TableStyle([("BACKGROUND",(0,0),(-1,-1),bg),
                                  ("TOPPADDING",(0,0),(-1,-1),5),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),5),
                                  ("LEFTPADDING",(0,0),(0,-1),10),
                                  ("LEFTPADDING",(1,0),(1,-1),6),
                                  ("RIGHTPADDING",(0,0),(-1,-1),8),
                                  ("LINEBELOW",(0,0),(-1,-2),0.5,colors.HexColor("#E6EDF3")),
                                  ("VALIGN",(0,0),(-1,-1),"TOP")]))

            card = Table([[header],[body]], colWidths=[CONTENT_W],
                style=TableStyle([("BOX",(0,0),(-1,-1),1,RED),
                                  ("BACKGROUND",(0,0),(-1,0),GRAY_LIGHT),
                                  ("TOPPADDING",(0,0),(-1,0),8),
                                  ("BOTTOMPADDING",(0,0),(-1,0),8),
                                  ("LEFTPADDING",(0,0),(-1,0),10),
                                  ("RIGHTPADDING",(0,0),(-1,0),10),
                                  ("TOPPADDING",(0,1),(-1,-1),0),
                                  ("BOTTOMPADDING",(0,1),(-1,-1),0),
                                  ("LEFTPADDING",(0,1),(-1,-1),0),
                                  ("RIGHTPADDING",(0,1),(-1,-1),0)]))
            story.append(KeepTogether([card, Spacer(1,8)]))

    story.append(PageBreak())

    # ── 9. REMEDIATION ROADMAP ────────────────────────────────────────────────
    story.append(Paragraph("9. Remediation Roadmap", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=10))

    PRIORITY = [
        ("Immediate (0–7 days)",    ["IAM"],           RED,    RED_LIGHT),
        ("Short-term (7–30 days)",  ["S3","Logging"],  ORANGE, ORANGE_LIGHT),
        ("Medium-term (30–90 days)",["Monitoring"],    BLUE,   BLUE_LIGHT),
        ("Low priority (90+ days)", ["Networking"],    GREEN,  GREEN_LIGHT),
    ]
    for phase, sections, fg, bg in PRIORITY:
        phase_ctrls = [c for c in CONTROLS
                       if c["section"] in sections
                       and results.get(c["id"],{}).get("status") == "FAIL"]
        if not phase_ctrls: continue

        ph_hdr = Table([[
            Paragraph(f"<b>{phase}</b>",
                      ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=10, textColor=fg, leading=13)),
            Table([[Paragraph(sections[0] if len(sections)==1 else "/".join(sections),
                              ParagraphStyle("pt", fontName="Helvetica-Bold", fontSize=7,
                                             textColor=fg, alignment=TA_CENTER))]],
                  colWidths=[55],
                  style=TableStyle([("BACKGROUND",(0,0),(-1,-1),bg),
                                    ("BOX",(0,0),(-1,-1),0.5,fg),
                                    ("TOPPADDING",(0,0),(-1,-1),3),
                                    ("BOTTOMPADDING",(0,0),(-1,-1),3)])),
        ]], colWidths=[CONTENT_W-62, 60],
           style=TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                             ("ALIGN",(1,0),(-1,-1),"RIGHT")]))

        story.append(Table([[ph_hdr]], colWidths=[CONTENT_W],
            style=TableStyle([("BOX",(0,0),(-1,-1),1,fg),
                              ("BACKGROUND",(0,0),(-1,-1),GRAY_LIGHT),
                              ("TOPPADDING",(0,0),(-1,-1),8),
                              ("BOTTOMPADDING",(0,0),(-1,-1),8),
                              ("LEFTPADDING",(0,0),(-1,-1),10),
                              ("RIGHTPADDING",(0,0),(-1,-1),10)])))

        for ctrl in phase_ctrls:
            story.append(Table([[Paragraph(
                f"→  <b>{ctrl['id']}</b>: {ctrl['title']}  "
                f"<font color='#6E7681' size='8'>({ctrl['section']})</font>", ST["body"])]],
                colWidths=[CONTENT_W],
                style=TableStyle([("BACKGROUND",(0,0),(-1,-1),bg),
                                  ("LEFTPADDING",(0,0),(-1,-1),16),
                                  ("TOPPADDING",(0,0),(-1,-1),5),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),5),
                                  ("BOX",(0,0),(-1,-1),0.5,fg),
                                  ("LINEBELOW",(0,0),(-1,-1),0.5,colors.HexColor("#E6EDF3"))])))
        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ── 10. APPENDIX ──────────────────────────────────────────────────────────
    story.append(Paragraph("10. Appendix — All Controls Reference", ST["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PURPLE, spaceAfter=10))

    app_rows = [[
        Paragraph("<b>ID</b>",        ST["th"]),
        Paragraph("<b>Section</b>",   ST["th"]),
        Paragraph("<b>Control</b>",   ST["th"]),
        Paragraph("<b>Status</b>",    ST["th"]),
        Paragraph("<b>Reference</b>", ST["th"]),
    ]]
    for ctrl in CONTROLS:
        fg, bg = SECTION_COLORS.get(ctrl["section"], (GRAY, GRAY_LIGHT))
        r   = results.get(ctrl["id"], {"status":"N/A"})
        st  = r["status"]
        c   = GREEN if st=="PASS" else RED if st=="FAIL" else ORANGE if st=="ERROR" else GRAY
        app_rows.append([
            Paragraph(ctrl["id"],      ST["td_mono"]),
            Paragraph(ctrl["section"], ParagraphStyle("sn", fontSize=8, fontName="Helvetica-Bold", textColor=fg, leading=11)),
            Paragraph(ctrl["title"],   ST["small"]),
            Paragraph(f'<font color="{c.hexval()}"><b>{st}</b></font>',
                      ParagraphStyle("sr", fontSize=8, fontName="Helvetica-Bold", textColor=c, alignment=TA_CENTER, leading=11)),
            Paragraph(ctrl["reference"], ParagraphStyle("ref", fontSize=7, textColor=GRAY, leading=10)),
        ])

    story.append(Table(app_rows,
        colWidths=[CONTENT_W*0.09, CONTENT_W*0.13, CONTENT_W*0.35, CONTENT_W*0.10, CONTENT_W*0.33],
        style=TableStyle([("BACKGROUND",(0,0),(-1,0),DARK),
                          ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,GRAY_LIGHT]),
                          ("TOPPADDING",(0,0),(-1,-1),5),
                          ("BOTTOMPADDING",(0,0),(-1,-1),5),
                          ("LEFTPADDING",(0,0),(-1,-1),6),
                          ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#E6EDF3")),
                          ("VALIGN",(0,0),(-1,-1),"TOP")])))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"This report was prepared by {consultant['name']} ({consultant['title']}) on {scan_date}. "
        f"All results reflect the state of the AWS environment at time of assessment. "
        f"Re-assess after remediation to verify compliance improvements. "
        f"Contact: {consultant['email']}",
        ParagraphStyle("cl", fontName="Helvetica", fontSize=8.5, textColor=GRAY,
                       leading=13, alignment=TA_CENTER)))

    def make_canvas(*a, **kw):
        kw["meta"] = meta
        return CISCanvas(*a, **kw)

    doc.build(story, canvasmaker=make_canvas)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        consultant, client, creds, output_path = collect_inputs()

        sep("CONNECTING TO AWS")
        session = connect(creds)
        print(f"  {green('✓')} Connected ({creds['region']})")

        results = run_checks(session)
        summary = calc_score(results)

        sep("GENERATING PDF REPORT")
        print(f"  Compliance Score : {summary['score']}/100 — {summary['rating']}")
        print(f"  Controls Passed  : {summary['passed']} / {summary['total']}")
        print(f"  Controls Failed  : {summary['failed']}")
        print(f"  Output           : {output_path}\n")
        print(f"  ⏳ Building PDF...")

        generate_pdf(output_path, consultant, client, creds, results, summary)

        print(f"\n{bold('╔══════════════════════════════════════════════════════════╗')}")
        print(f"{bold('║')}  {green('✅ REPORT READY')}: {output_path:<38}{bold('║')}")
        print(f"{bold('╚══════════════════════════════════════════════════════════╝')}\n")

    except KeyboardInterrupt:
        print(f"\n\n  {yellow('⚠  Cancelled. No report generated.')}\n")
