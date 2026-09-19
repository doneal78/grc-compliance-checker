# AWS GRC Compliance Checker

A Python tool that connects to a live AWS account using boto3 and evaluates S3 buckets and IAM configurations against common security and compliance controls. Generates a unified compliance report with an overall score and rating.

Part of the OracleRecon GRC Engineering Portfolio.

---

## What it does

The tool runs three compliance checks across two AWS service areas and produces a single timestamped JSON report with an overall compliance score rated GOOD, NEEDS IMPROVEMENT, or AT RISK.

**S3 checks per bucket**

Server-side encryption: verifies AES-256 or KMS encryption is configured.

Public access blocking: verifies all four public access block flags are set to true (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets).

Versioning: verifies versioning is enabled.

**IAM checks**

Password policy: validates minimum length, complexity requirements, maximum password age, and reuse prevention.

MFA enforcement: checks every IAM user for at least one registered MFA device.

Root access keys: verifies no active access keys exist on the root account.

Inactive users: identifies IAM users with no login activity in the past 90 days.

---

## Results from a live AWS account

Before the Project 3 Terraform baseline was applied, the OracleRecon AWS account scored 40% AT RISK. After deploying the baseline, the same checker confirmed the score improved to 78% NEEDS IMPROVEMENT. The remaining failures were one intentionally misconfigured test bucket and MFA on the lab IAM user which requires physical device setup.

---

## Setup

```
pip install boto3 rich
```

Configure AWS credentials:

```
aws configure
```

The IAM user needs these read-only managed policies: AmazonS3ReadOnlyAccess, IAMReadOnlyAccess, SecurityAudit.

---

## Usage

Run all checks and generate the unified report:

```
py compliance_checker.py
```

Run individual checkers:

```
py s3_checker.py
py iam_checker.py
```

---

## Output

Each run produces a timestamped JSON report and a color-coded terminal table. The unified report combines S3 and IAM results with an overall compliance score percentage and rating.

---

## Files

`s3_checker.py` scans all S3 buckets and checks encryption, public access blocking, and versioning.

`iam_checker.py` checks password policy, MFA per user, root access keys, and inactive users.

`compliance_checker.py` imports both checkers, combines results, and generates the unified report.

---

## Related projects

Project 3 Terraform Baseline: https://github.com/doneal78/grc-terraform-baseline

The Terraform baseline fixes the findings this tool identifies. Running this checker before and after applying the baseline shows the compliance score improvement in real numbers.

Full portfolio: https://github.com/doneal78
