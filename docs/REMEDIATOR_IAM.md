# IAM permissions for Fixing Options (real AWS)

VaultScan **scan** often uses a **read-only** role (`SecurityAudit` / custom view-only).

**Fixing Options → Apply** does **not** use that scan role. It uses:

1. Your **base Access Key** from Settings (direct), or  
2. Optional **remediator role** if you set `remediator_role_arn` later  

So the IAM **user** (or remediator role) must be allowed to **write** the APIs below.

## Minimal policy for common auto-fixes

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3Hardening",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucket*",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketAcl",
        "s3:PutBucketEncryption",
        "s3:PutBucketVersioning",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Ec2NetworkAndImds",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceMetadataOptions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IamDetach",
      "Effect": "Allow",
      "Action": [
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:GetRole",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "StsIdentity",
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity", "sts:AssumeRole"],
      "Resource": "*"
    }
  ]
}
```

Attach this (or tighter Resource ARNs) to the **same IAM user** whose Access Key you paste in Settings.

## Workflow

1. Settings → Access Key + Secret (write-capable user) + scan Role ARN (read-only OK)  
2. Scan (uses AssumeRole when configured)  
3. Fixing options → PLAN ALL AUTO-FIXES → type `APPLY` → APPLY FIXES  
4. Each action shows **applied** or **failed** with AWS error text  
5. Re-scan reads **live AWS** — fixed resources should no longer alert  

## If nothing changes

- Expand failed actions: look for `AccessDenied`  
- Confirm Settings keys are for a user that has the write policy  
- Scan role can stay read-only; **keys** must write  
- Some rules (MFA enroll, complex KMS) stay manual by design  
