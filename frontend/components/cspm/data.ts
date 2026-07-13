export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type LogLevel = "INF" | "MED" | "CRIT";

export const NAV_ITEMS = [
  { id: "overview", label: "OVERVIEW", code: "01" },
  { id: "findings", label: "FINDINGS", code: "02" },
  { id: "attackpaths", label: "ATTACK PATHS", code: "03" },
  { id: "remediate", label: "AI FIX", code: "04" },
  { id: "history", label: "SCAN HISTORY", code: "05" },
  { id: "settings", label: "SETTINGS", code: "06" },
] as const;

export type TabId = (typeof NAV_ITEMS)[number]["id"];

export const postureTrend = [
  { t: "00:00", score: 62 },
  { t: "02:00", score: 68 },
  { t: "04:00", score: 64 },
  { t: "06:00", score: 71 },
  { t: "08:00", score: 79 },
  { t: "10:00", score: 74 },
  { t: "12:00", score: 83 },
  { t: "14:00", score: 88 },
  { t: "16:00", score: 92 },
  { t: "18:00", score: 87 },
  { t: "20:00", score: 94 },
  { t: "22:00", score: 100 },
];

export const infraStatus = [
  { label: "TARGET SERVICE", value: "AWS-PROD-EU-WEST-1", state: "online" as const },
  { label: "SCAN ENGINE", value: "VLT-ENGINE v4.2.1", state: "online" as const },
  { label: "DB RECORD LOGS", value: "1,284,930 EVENTS", state: "syncing" as const },
];

export const vulnerabilities: {
  id: string;
  service: string;
  severity: Severity;
  description: string;
}[] = [
  {
    id: "arn:s3:vault-backups-01",
    service: "S3",
    severity: "CRITICAL",
    description: "Bucket policy allows public READ/WRITE to sensitive backup objects.",
  },
  {
    id: "sg-0f8a12bce9",
    service: "EC2",
    severity: "CRITICAL",
    description: "Security group exposes port 22 (SSH) to 0.0.0.0/0.",
  },
  {
    id: "iam::role/deploy-admin",
    service: "IAM",
    severity: "HIGH",
    description: "Role attached with wildcard '*:*' administrative permissions.",
  },
  {
    id: "rds:core-postgres-prod",
    service: "RDS",
    severity: "HIGH",
    description: "Storage encryption at rest is disabled on production database.",
  },
  {
    id: "kms:key/legacy-2019",
    service: "KMS",
    severity: "MEDIUM",
    description: "Automatic key rotation not enabled on active CMK.",
  },
  {
    id: "cloudtrail:org-trail",
    service: "TRAIL",
    severity: "MEDIUM",
    description: "Log file validation is not enabled for the organization trail.",
  },
  {
    id: "lambda:img-resizer",
    service: "LAMBDA",
    severity: "LOW",
    description: "Function runtime nodejs14.x is deprecated and unsupported.",
  },
];

export const complianceFrameworks = [
  {
    name: "CIS AWS Foundations Benchmark",
    version: "v1.4.0",
    status: "PASSING" as const,
    passed: 47,
    total: 52,
    controls: [
      { label: "Identity & Access Management", value: 96 },
      { label: "Logging", value: 92 },
      { label: "Monitoring", value: 88 },
      { label: "Networking", value: 90 },
    ],
  },
  {
    name: "NIST SP 800-53",
    version: "Rev. 5",
    status: "FAILING" as const,
    passed: 61,
    total: 94,
    controls: [
      { label: "Access Control (AC)", value: 72 },
      { label: "Audit & Accountability (AU)", value: 58 },
      { label: "System & Comms (SC)", value: 41 },
      { label: "Config Management (CM)", value: 66 },
    ],
  },
];

export const remediationPlaybook = {
  title: "AUTO-REMEDIATE: S3 PUBLIC EXPOSURE",
  target: "arn:s3:vault-backups-01",
  lines: [
    "$ vaultscan remediate --resource arn:s3:vault-backups-01",
    "[*] Fetching current bucket ACL ...",
    "[*] Detected: PublicRead + PublicWrite grants",
    "[>] Applying BlockPublicAcls = true",
    "[>] Applying IgnorePublicAcls = true",
    "[>] Applying RestrictPublicBuckets = true",
    "[>] Enabling default SSE-KMS encryption",
    "[OK] Public access blocked successfully",
    "[OK] Posture score recalculated: 83 -> 100",
    "$ _",
  ],
  steps: [
    { id: 1, label: "Isolate exposed resource", done: true },
    { id: 2, label: "Apply block-public-access policy", done: true },
    { id: 3, label: "Enable KMS encryption at rest", done: true },
    { id: 4, label: "Verify & re-scan target", done: false },
  ],
};

export const scanHistory = [
  { id: "SCAN-1042", timestamp: "2025-07-07 12:00:04", score: 100, critical: 0 },
  { id: "SCAN-1041", timestamp: "2025-07-07 06:00:01", score: 83, critical: 2 },
  { id: "SCAN-1040", timestamp: "2025-07-06 18:00:03", score: 87, critical: 1 },
  { id: "SCAN-1039", timestamp: "2025-07-06 06:00:02", score: 74, critical: 4 },
  { id: "SCAN-1038", timestamp: "2025-07-05 18:00:05", score: 79, critical: 3 },
  { id: "SCAN-1037", timestamp: "2025-07-05 06:00:00", score: 64, critical: 6 },
  { id: "SCAN-1036", timestamp: "2025-07-04 18:00:04", score: 68, critical: 5 },
  { id: "SCAN-1035", timestamp: "2025-07-04 06:00:01", score: 62, critical: 7 },
];

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function getSeverityCounts() {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: vulnerabilities.filter((v) => v.severity === severity).length,
  }));
}

export const latestScan = scanHistory[0];

export const scanReportMeta = {
  reportId: "RPT-1042",
  generatedFor: "AWS-PROD-EU-WEST-1",
  engine: "VLT-ENGINE v4.2.1",
  operator: "SEC-OPERATOR",
  window: "2025-07-07 00:00 → 12:00 UTC",
};

export const auditStream: {
  level: LogLevel;
  header: string;
  message: string;
  time: string;
}[] = [
  {
    level: "CRIT",
    header: "PUBLIC S3 BUCKET DETECTED",
    message: "vault-backups-01 exposed to public internet.",
    time: "12:00:04",
  },
  {
    level: "INF",
    header: "SCAN COMPLETED",
    message: "Full sweep of AWS-PROD-EU-WEST-1 finished.",
    time: "12:00:02",
  },
  {
    level: "MED",
    header: "KMS ROTATION DISABLED",
    message: "Key legacy-2019 has no rotation policy.",
    time: "11:58:41",
  },
  {
    level: "CRIT",
    header: "SSH OPEN TO WORLD",
    message: "sg-0f8a12bce9 allows 0.0.0.0/0 on :22.",
    time: "11:57:12",
  },
  {
    level: "INF",
    header: "REMEDIATION APPLIED",
    message: "Block-public-access enforced on 3 buckets.",
    time: "11:55:30",
  },
  {
    level: "MED",
    header: "IAM DRIFT DETECTED",
    message: "deploy-admin gained wildcard permissions.",
    time: "11:52:08",
  },
  {
    level: "INF",
    header: "ENGINE HEARTBEAT",
    message: "VLT-ENGINE v4.2.1 nominal, latency 42ms.",
    time: "11:50:00",
  },
  {
    level: "CRIT",
    header: "UNENCRYPTED RDS INSTANCE",
    message: "core-postgres-prod storage not encrypted.",
    time: "11:47:19",
  },
];
