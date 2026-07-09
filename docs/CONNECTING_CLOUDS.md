# Connecting to Different Clouds in VaultScan

## 1. Fully Simulated Empty Cloud (Recommended for Testing & Development)

This gives you a **completely empty, fully controllable AWS-like environment** via terminal.

### Options

| Method       | Command                          | Speed | Docker | Best For                  |
|--------------|----------------------------------|-------|--------|---------------------------|
| **Moto**     | `python scanner.py --simulate`   | Instant | No     | Demos, CI, daily dev     |
| **LocalStack** | `python scanner.py --localstack` | Fast  | Yes    | More realistic simulation |

### Control it from terminal

```bash
# Using awslocal (when LocalStack is running)
awslocal s3 mb s3://my-test-bucket
awslocal s3api put-bucket-acl --bucket my-test-bucket --acl public-read

# Or using Python
python -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', aws_access_key_id='test', aws_secret_access_key='test')
s3.create_bucket(Bucket='evil-bucket')
print('Bucket created in simulated cloud')
"
```

You have full control. You can create any bad configuration you want to test the scanner.

---

## 2. Real AWS

### How to connect VaultScan to real AWS

VaultScan uses the standard `boto3` library, so it supports all normal AWS authentication methods.

#### Option A — Using AWS CLI profiles (Recommended)

```bash
# 1. Configure your profile once
aws configure --profile vaultscan-readonly

# 2. Run scanner against real account
python scanner.py --aws --profile vaultscan-readonly --region us-east-1
```

#### Option B — Environment variables

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

python scanner.py --aws
```

#### Option C — IAM Role (Best for production / team use)

This is what you will use in the final web platform.

1. In the target AWS account, create an IAM Role:
   - Trusted entity: Another AWS account (or your VaultScan account)
   - Attach read-only policies: `SecurityAudit`, `ViewOnlyAccess`, or custom policy with only `s3:*`, `iam:*`, `ec2:Describe*` etc.

2. Run scanner with role assumption (we can add this later).

---

## 3. How the Code Switches Between Them

See the improved `get_client()` in `scanner.py`:

```python
python scanner.py --simulate      # Moto (empty cloud)
python scanner.py --localstack    # LocalStack
python scanner.py --aws           # Real AWS
python scanner.py --aws --profile mycompany-readonly
```

The same check functions (`check_s3`, `check_iam`, ...) work in all modes.

---

## 4. For the Future Web Platform / UI

You said: *"that is gonna be site with ui but we are just testing just. so in the platform we have to have simply thing to connect others"*

### Recommended Design (Simple & Secure)

**"Connect Account" flow in the UI:**

1. User clicks **"Connect AWS Account"**
2. We show two options:

   **A. Quick Test (Temporary Keys)**
   - Paste Access Key + Secret
   - Only for testing / personal use
   - We store them encrypted temporarily

   **B. Secure Connection (Recommended)**
   - Instructions:
     1. Go to your AWS account
     2. Create an IAM Role with these permissions: [list minimal read-only actions]
     3. Paste the **Role ARN** + **External ID**
   - VaultScan assumes the role when scanning (no long-lived keys stored)

3. We save the connection as:
   ```json
   {
     "provider": "aws",
     "name": "Production Account",
     "connection_type": "assume_role",
     "role_arn": "arn:aws:iam::123456789012:role/VaultScan-ReadOnly",
     "external_id": "vaultscan-prod-xyz",
     "regions": ["us-east-1", "eu-west-1"]
   }
   ```

This is the industry standard (used by Wiz, Orca, Prisma Cloud, etc.).

### Advantages
- No permanent keys stored
- User controls exactly what we can read
- Easy to revoke (just delete the role)
- Works great with multiple accounts

---

## 5. Next Steps for VaultScan

Current priority:
- [x] Support `--simulate`, `--localstack`, `--aws`
- [ ] Add AssumeRole support for real AWS
- [ ] Store connection profiles (in a `connections/` folder or database)
- [ ] When you build the UI, the "Add Account" page will use the patterns above

Would you like me to:
- Add AssumeRole support to the scanner?
- Create a `connections.py` helper module?
- Make a simple web form prototype (Flask) for connecting accounts?

Let me know how you want to shape the "connect others" part.