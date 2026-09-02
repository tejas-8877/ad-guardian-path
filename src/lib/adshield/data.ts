/**
 * Fixture domain mirroring the FastAPI MockADConnector (corp.local).
 * The React app talks to this module through `api.ts`, so swapping in the
 * live backend later is a one-file change.
 */

export type Role = "standard_user" | "it_support" | "security_admin";
export type Severity = "critical" | "high" | "medium" | "low";
export type PrincipalType = "user" | "group" | "computer" | "gpo";

export interface Principal {
  objectSid: string;
  samAccountName: string;
  displayName: string;
  type: PrincipalType;
  enabled: boolean;
  adminCount: boolean;
  domainController: boolean;
  spns: string[];
  passwordAgeDays: number | null;
  lastLogonDays: number | null;
  os?: string;
  description?: string;
}

export interface Finding {
  id: string;
  rule: string;
  title: string;
  severity: Severity;
  principalSid: string;
  principalName: string;
  description: string;
  remediation: string;
  mitre: string;
}

export interface PathStep {
  sourceName: string;
  targetName: string;
  edgeType: string;
  cost: number;
}

export interface AttackPath {
  id: string;
  sourceName: string;
  targetName: string;
  hops: number;
  totalCost: number;
  severity: Severity;
  steps: PathStep[];
}

export interface SessionUser {
  samAccountName: string;
  displayName: string;
  objectSid: string;
  role: Role;
  permissions: string[];
}

const sid = (rid: number) => `S-1-5-21-1004336348-1177238915-682003330-${rid}`;

export const DOMAIN = "corp.local";

export const PRINCIPALS: Principal[] = [
  {
    objectSid: sid(1103),
    samAccountName: "j.doe",
    displayName: "Jane Doe",
    type: "user",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: 412,
    lastLogonDays: 1,
    description: "Service Desk analyst",
  },
  {
    objectSid: sid(1104),
    samAccountName: "t.admin",
    displayName: "Tom Admin",
    type: "user",
    enabled: true,
    adminCount: true,
    domainController: false,
    spns: [],
    passwordAgeDays: 96,
    lastLogonDays: 0,
  },
  {
    objectSid: sid(1105),
    samAccountName: "svc_sql",
    displayName: "SQL Service",
    type: "user",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: ["MSSQLSvc/sql01.corp.local:1433"],
    passwordAgeDays: 903,
    lastLogonDays: 2,
    description: "SQL svc - pwd in KeePass",
  },
  {
    objectSid: sid(1106),
    samAccountName: "svc_backup",
    displayName: "Backup Service",
    type: "user",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: ["BackupSvc/bkp01.corp.local"],
    passwordAgeDays: 1180,
    lastLogonDays: 4,
  },
  {
    objectSid: sid(1107),
    samAccountName: "m.chen",
    displayName: "Mei Chen",
    type: "user",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: 210,
    lastLogonDays: 187,
  },
  {
    objectSid: sid(1108),
    samAccountName: "r.patel",
    displayName: "Rohan Patel",
    type: "user",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: 44,
    lastLogonDays: 0,
  },
  {
    objectSid: sid(512),
    samAccountName: "Domain Admins",
    displayName: "Domain Admins",
    type: "group",
    enabled: true,
    adminCount: true,
    domainController: false,
    spns: [],
    passwordAgeDays: null,
    lastLogonDays: null,
  },
  {
    objectSid: sid(551),
    samAccountName: "Backup Operators",
    displayName: "Backup Operators",
    type: "group",
    enabled: true,
    adminCount: true,
    domainController: false,
    spns: [],
    passwordAgeDays: null,
    lastLogonDays: null,
  },
  {
    objectSid: sid(1201),
    samAccountName: "Helpdesk",
    displayName: "ADShield-Helpdesk",
    type: "group",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: null,
    lastLogonDays: null,
  },
  {
    objectSid: sid(1202),
    samAccountName: "SOC",
    displayName: "ADShield-SOC",
    type: "group",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: null,
    lastLogonDays: null,
  },
  {
    objectSid: sid(1001),
    samAccountName: "DC01$",
    displayName: "DC01",
    type: "computer",
    enabled: true,
    adminCount: false,
    domainController: true,
    spns: ["HOST/dc01.corp.local"],
    passwordAgeDays: 12,
    lastLogonDays: 0,
    os: "Windows Server 2022",
  },
  {
    objectSid: sid(1002),
    samAccountName: "SQL01$",
    displayName: "SQL01",
    type: "computer",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: ["MSSQLSvc/sql01.corp.local"],
    passwordAgeDays: 31,
    lastLogonDays: 0,
    os: "Windows Server 2019",
  },
  {
    objectSid: sid(1003),
    samAccountName: "WKS-042$",
    displayName: "WKS-042",
    type: "computer",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: 5,
    lastLogonDays: 0,
    os: "Windows 10 Pro (21H2, EOL)",
  },
  {
    objectSid: sid(1301),
    samAccountName: "Default Domain Policy",
    displayName: "Default Domain Policy",
    type: "gpo",
    enabled: true,
    adminCount: false,
    domainController: false,
    spns: [],
    passwordAgeDays: null,
    lastLogonDays: null,
  },
];

export const FINDINGS: Finding[] = [
  {
    id: "UNCONSTRAINED_DELEGATION:sql01",
    rule: "UNCONSTRAINED_DELEGATION",
    title: "Unconstrained Kerberos delegation enabled",
    severity: "critical",
    principalSid: sid(1002),
    principalName: "SQL01$",
    description:
      "TGTs of any authenticating principal — including Domain Admins — are cached on this host and can be extracted for full domain compromise.",
    remediation:
      "Switch to constrained delegation with protocol transition disabled, and add privileged accounts to Protected Users.",
    mitre: "T1550.003",
  },
  {
    id: "SECRET_IN_DESCRIPTION:svc_sql",
    rule: "SECRET_IN_DESCRIPTION",
    title: "Possible credential in object description",
    severity: "critical",
    principalSid: sid(1105),
    principalName: "svc_sql",
    description:
      "The description attribute is readable by every authenticated user and appears to reference credential material.",
    remediation: "Clear the attribute and rotate the exposed secret immediately.",
    mitre: "T1552.001",
  },
  {
    id: "AS_REP_ROASTABLE:m.chen",
    rule: "AS_REP_ROASTABLE",
    title: "Kerberos pre-authentication disabled",
    severity: "critical",
    principalSid: sid(1107),
    principalName: "m.chen",
    description:
      "Any unauthenticated host on the network can request an AS-REP for this account and crack it offline.",
    remediation: "Clear DONT_REQ_PREAUTH and rotate the password.",
    mitre: "T1558.004",
  },
  {
    id: "KERBEROASTABLE:svc_sql",
    rule: "KERBEROASTABLE",
    title: "Service account exposes SPN (Kerberoastable)",
    severity: "high",
    principalSid: sid(1105),
    principalName: "svc_sql",
    description:
      "MSSQLSvc/sql01.corp.local:1433 — any authenticated user can request a service ticket and crack it offline.",
    remediation: "Migrate to a gMSA or enforce a 25+ character random password.",
    mitre: "T1558.003",
  },
  {
    id: "KERBEROASTABLE:svc_backup",
    rule: "KERBEROASTABLE",
    title: "Service account exposes SPN (Kerberoastable)",
    severity: "high",
    principalSid: sid(1106),
    principalName: "svc_backup",
    description: "BackupSvc/bkp01.corp.local is registered on a Backup Operators member.",
    remediation: "Migrate to a gMSA and remove Backup Operators membership.",
    mitre: "T1558.003",
  },
  {
    id: "STALE_PASSWORD:svc_backup",
    rule: "STALE_PASSWORD",
    title: "Password unchanged for 1180 days",
    severity: "high",
    principalSid: sid(1106),
    principalName: "svc_backup",
    description: "Long-lived privileged credentials are prime targets for offline cracking.",
    remediation: "Rotate the credential and schedule automated rotation.",
    mitre: "T1110",
  },
  {
    id: "STALE_PASSWORD:j.doe",
    rule: "STALE_PASSWORD",
    title: "Password unchanged for 412 days",
    severity: "medium",
    principalSid: sid(1103),
    principalName: "j.doe",
    description: "Credential age exceeds the 365-day policy threshold.",
    remediation: "Force a password reset at next logon.",
    mitre: "T1110",
  },
  {
    id: "DORMANT_ACCOUNT:m.chen",
    rule: "DORMANT_ACCOUNT",
    title: "Enabled but dormant account",
    severity: "medium",
    principalSid: sid(1107),
    principalName: "m.chen",
    description: "No logon in 187 days while the account remains enabled.",
    remediation: "Disable and move to a quarantine OU.",
    mitre: "T1078",
  },
  {
    id: "PASSWORD_NEVER_EXPIRES:svc_sql",
    rule: "PASSWORD_NEVER_EXPIRES",
    title: "Password set to never expire",
    severity: "medium",
    principalSid: sid(1105),
    principalName: "svc_sql",
    description: "Credential lifetime is unbounded, extending the window of a leak.",
    remediation: "Remove DONT_EXPIRE_PASSWORD and enforce rotation.",
    mitre: "T1078.002",
  },
  {
    id: "LEGACY_OS:WKS-042",
    rule: "LEGACY_OS",
    title: "Workstation running end-of-life OS build",
    severity: "low",
    principalSid: sid(1003),
    principalName: "WKS-042$",
    description: "Windows 10 21H2 no longer receives security updates.",
    remediation: "Upgrade to a supported servicing channel.",
    mitre: "T1190",
  },
];

export const ATTACK_PATHS: AttackPath[] = [
  {
    id: "p1",
    sourceName: "j.doe",
    targetName: "DC01$",
    hops: 4,
    totalCost: 4.5,
    severity: "critical",
    steps: [
      { sourceName: "j.doe", targetName: "Helpdesk", edgeType: "MemberOf", cost: 0.5 },
      {
        sourceName: "Helpdesk",
        targetName: "svc_backup",
        edgeType: "ForceChangePassword",
        cost: 2.5,
      },
      {
        sourceName: "svc_backup",
        targetName: "Backup Operators",
        edgeType: "MemberOf",
        cost: 0.5,
      },
      { sourceName: "Backup Operators", targetName: "DC01$", edgeType: "AdminTo", cost: 1.0 },
    ],
  },
  {
    id: "p2",
    sourceName: "t.admin",
    targetName: "Domain Admins",
    hops: 1,
    totalCost: 2.0,
    severity: "critical",
    steps: [
      { sourceName: "t.admin", targetName: "Domain Admins", edgeType: "GenericAll", cost: 2.0 },
    ],
  },
  {
    id: "p3",
    sourceName: "svc_sql",
    targetName: "DC01$",
    hops: 2,
    totalCost: 5.0,
    severity: "high",
    steps: [
      {
        sourceName: "svc_sql",
        targetName: "SQL01$",
        edgeType: "AllowedToDelegate",
        cost: 3.5,
      },
      { sourceName: "SQL01$", targetName: "DC01$", edgeType: "HasDCSync", cost: 1.5 },
    ],
  },
  {
    id: "p4",
    sourceName: "r.patel",
    targetName: "Backup Operators",
    hops: 3,
    totalCost: 6.0,
    severity: "high",
    steps: [
      { sourceName: "r.patel", targetName: "WKS-042$", edgeType: "CanRDP", cost: 2.0 },
      { sourceName: "WKS-042$", targetName: "svc_backup", edgeType: "HasSession", cost: 1.5 },
      {
        sourceName: "svc_backup",
        targetName: "Backup Operators",
        edgeType: "MemberOf",
        cost: 0.5,
      },
    ],
  },
  {
    id: "p5",
    sourceName: "Helpdesk",
    targetName: "Domain Admins",
    hops: 3,
    totalCost: 8.5,
    severity: "medium",
    steps: [
      { sourceName: "Helpdesk", targetName: "svc_sql", edgeType: "WriteDacl", cost: 3.0 },
      { sourceName: "svc_sql", targetName: "t.admin", edgeType: "GenericWrite", cost: 2.5 },
      { sourceName: "t.admin", targetName: "Domain Admins", edgeType: "GenericAll", cost: 2.0 },
    ],
  },
];

export const RISK_TREND = [
  { week: "W-7", score: 81, findings: 22 },
  { week: "W-6", score: 78, findings: 21 },
  { week: "W-5", score: 74, findings: 19 },
  { week: "W-4", score: 76, findings: 20 },
  { week: "W-3", score: 68, findings: 16 },
  { week: "W-2", score: 63, findings: 14 },
  { week: "W-1", score: 59, findings: 12 },
  { week: "Now", score: 54, findings: 10 },
];

/** Demo accounts — mirrors the mock connector's RBAC group mapping. */
export const DEMO_ACCOUNTS: Record<string, { password: string; user: SessionUser }> = {
  "j.doe": {
    password: "Passw0rd!",
    user: {
      samAccountName: "j.doe",
      displayName: "Jane Doe",
      objectSid: sid(1103),
      role: "standard_user",
      permissions: ["view:own_hygiene", "submit:malware_sample"],
    },
  },
  "r.patel": {
    password: "Passw0rd!",
    user: {
      samAccountName: "r.patel",
      displayName: "Rohan Patel",
      objectSid: sid(1108),
      role: "it_support",
      permissions: [
        "view:own_hygiene",
        "view:assets",
        "submit:malware_sample",
        "view:malware_analysis",
      ],
    },
  },
  "t.admin": {
    password: "Passw0rd!",
    user: {
      samAccountName: "t.admin",
      displayName: "Tom Admin",
      objectSid: sid(1104),
      role: "security_admin",
      permissions: [
        "view:own_hygiene",
        "view:assets",
        "view:findings",
        "view:attack_paths",
        "run:scan",
        "submit:malware_sample",
        "view:malware_analysis",
        "export:reports",
      ],
    },
  },
};

/** Directed, abusable relationship — mirrors ADEdge in the FastAPI backend. */
export interface Edge {
  sourceSid: string;
  targetSid: string;
  edgeType: string;
  note?: string;
}

export const EDGES: Edge[] = [
  { sourceSid: sid(1103), targetSid: sid(1201), edgeType: "MemberOf" },
  { sourceSid: sid(1107), targetSid: sid(1201), edgeType: "MemberOf" },
  { sourceSid: sid(1104), targetSid: sid(1202), edgeType: "MemberOf" },
  { sourceSid: sid(1106), targetSid: sid(551), edgeType: "MemberOf" },
  {
    sourceSid: sid(1201),
    targetSid: sid(1106),
    edgeType: "ForceChangePassword",
    note: "Helpdesk can reset svc_backup without knowing the old password",
  },
  {
    sourceSid: sid(1201),
    targetSid: sid(1105),
    edgeType: "WriteDacl",
    note: "Helpdesk can rewrite the svc_sql ACL",
  },
  {
    sourceSid: sid(1105),
    targetSid: sid(1104),
    edgeType: "GenericWrite",
    note: "svc_sql can set an SPN on t.admin (targeted Kerberoast)",
  },
  {
    sourceSid: sid(1104),
    targetSid: sid(512),
    edgeType: "GenericAll",
    note: "Unexpected GenericAll on Domain Admins",
  },
  { sourceSid: sid(551), targetSid: sid(1001), edgeType: "AdminTo", note: "Backup Operators local admin on DC01" },
  { sourceSid: sid(512), targetSid: sid(1001), edgeType: "AdminTo" },
  {
    sourceSid: sid(1105),
    targetSid: sid(1002),
    edgeType: "AllowedToDelegate",
    note: "Unconstrained delegation on SQL01",
  },
  { sourceSid: sid(1002), targetSid: sid(1001), edgeType: "HasDCSync", note: "DS-Replication-Get-Changes-All" },
  { sourceSid: sid(1108), targetSid: sid(1003), edgeType: "CanRDP" },
  { sourceSid: sid(1106), targetSid: sid(1003), edgeType: "HasSession", note: "Privileged session cached on WKS-042" },
  { sourceSid: sid(1003), targetSid: sid(1106), edgeType: "HasSession", note: "Credentials harvestable from LSASS" },
  { sourceSid: sid(1105), targetSid: sid(1002), edgeType: "HasSession" },
  { sourceSid: sid(1301), targetSid: sid(1003), edgeType: "GpLink" },
];

export type EndpointStatus = "clean" | "suspicious" | "malicious" | "unknown";

export interface EndpointRecord {
  endpointId: string;
  hostname: string;
  os?: string;
  status: EndpointStatus;
  lastSeen: string;
  detection?: string;
  loggedOnUser?: string;
}

/** Endpoint telemetry inventory (mirrors GET /api/endpoints). */
export const ENDPOINTS: EndpointRecord[] = [
  {
    endpointId: sid(1003),
    hostname: "WKS-042",
    os: "Windows 10 Pro (21H2, EOL)",
    status: "malicious",
    lastSeen: "2 minutes ago",
    detection: "Mimikatz-like credential access (YARA: CredDump_Generic)",
    loggedOnUser: "r.patel",
  },
  {
    endpointId: sid(1002),
    hostname: "SQL01",
    os: "Windows Server 2019",
    status: "suspicious",
    lastSeen: "11 minutes ago",
    detection: "Packed binary dropped in C:\\Windows\\Temp (entropy 7.82)",
    loggedOnUser: "svc_sql",
  },
  {
    endpointId: sid(1001),
    hostname: "DC01",
    os: "Windows Server 2022",
    status: "clean",
    lastSeen: "just now",
  },
];

/** Directory connection banner (mirrors GET /api/ad/health). */
export const AD_CONNECTION = {
  connected: true,
  connector: "mock" as "mock" | "real",
  domain: DOMAIN,
  server: `DC01.${DOMAIN}`,
  protocol: "LDAPS",
  port: 636,
  baseDn: "DC=corp,DC=local",
  latencyMs: 12,
};
