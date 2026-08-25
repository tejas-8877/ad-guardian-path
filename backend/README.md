# ADShield — Backend (FastAPI)

## Phase 1 — Directory structure

### Backend
```text
backend/
├── app/
│   ├── main.py                     # FastAPI app factory, CORS, error handlers, router mount
│   ├── api/
│   │   ├── deps.py                 # ✅ current-user, role & permission guards
│   │   └── routes/
│   │       ├── auth.py             # ✅ POST /auth/login, GET /auth/me
│   │       ├── me.py               # personal hygiene + risk score (standard users)
│   │       ├── assets.py           # users / groups / computers / GPOs (IT+)
│   │       ├── findings.py         # vulnerability findings (SOC)
│   │       ├── attack_paths.py     # graph + shortest-path queries (SOC)
│   │       ├── endpoint.py         # POST /api/endpoint/scan-file
│   │       ├── collection.py       # trigger AD collection runs
│   │       └── reports.py          # export PDF/CSV
│   ├── connectors/
│   │   ├── base.py                 # ✅ ADConnector ABC + ADPrincipal/ADEdge/ADIdentity
│   │   ├── mock_ad.py              # ✅ fixture domain w/ realistic attack chain
│   │   ├── real_ad.py              # ✅ ldap3 LDAPS collection + ACE→edge parsing
│   │   └── factory.py              # ✅ mock/real switch (ADSHIELD_AD_CONNECTOR)
│   ├── core/
│   │   ├── config.py               # ✅ pydantic-settings, env-only secrets
│   │   ├── security.py             # ✅ JWT issue/verify
│   │   ├── rbac.py                 # ✅ Role, Permission, AD-group→role mapping
│   │   ├── logging.py              # structured audit logging
│   │   └── db.py                   # SQLAlchemy engine / session
│   ├── models/                     # SQLAlchemy ORM (principals, edges, findings, scans…)
│   ├── schemas/
│   │   └── auth.py                 # ✅ login/profile Pydantic models
│   ├── services/
│   │   ├── graph_engine.py         # build graph, BFS/Dijkstra shortest path
│   │   ├── risk_scoring.py         # per-principal + domain risk scores
│   │   ├── hygiene.py              # password age, stale accounts, delegation
│   │   ├── findings_engine.py      # rule pack → findings w/ severity
│   │   └── malware/
│   │       ├── engine.py           # orchestration + verdict
│   │       ├── pe_analysis.py      # pefile structure checks
│   │       ├── entropy.py          # Shannon entropy / packing detection
│   │       └── yara_scanner.py     # YARA rule matching
│   ├── rules/                      # .yar rule packs
│   └── migrations/                 # Alembic
├── tests/
└── requirements.txt                # ✅
```
`✅` = written in Phase 2.

### Frontend (Phase 3 — TanStack Start, React 19 + Vite + Tailwind)
```text
src/
├── routes/
│   ├── __root.tsx                  # providers, toaster, error boundary
│   ├── index.tsx                   # login (domain credentials)
│   ├── _app/route.tsx              # authenticated shell: sidebar + topbar
│   ├── _app/dashboard.tsx          # SOC overview (Recharts)
│   ├── _app/my-security.tsx        # standard-user hygiene + risk score
│   ├── _app/assets.$type.tsx       # users/groups/computers tables
│   ├── _app/findings.tsx
│   ├── _app/attack-paths.tsx       # Cytoscape.js graph + node inspector
│   ├── _app/malware.tsx            # endpoint scan submissions & verdicts
│   └── _app/reports.tsx
├── components/
│   ├── ui/                         # shadcn primitives (slate SOC theme)
│   ├── data-table/                 # search + column filters + pagination
│   ├── charts/                     # severity donut, trend, top-risk bars
│   ├── graph/CytoscapeGraph.tsx    # client-only, lazy-loaded
│   └── skeletons/
├── features/                       # api hooks per domain (TanStack Query)
├── lib/api-client.ts               # fetch wrapper, bearer token, 401 handling
├── lib/auth.tsx                    # session context + <RequirePermission>
└── styles.css                      # slate palette + severity tokens
```

## Phase 2 — What's implemented

**Connector abstraction** — `ADConnector` ABC defines `authenticate`, `get_users/groups/computers/gpos`, and `get_edges`. Both connectors return the same `ADPrincipal` / `ADEdge` dataclasses, so the graph engine, RBAC, and every API route are connector-agnostic. Switch with one env var:

```bash
ADSHIELD_AD_CONNECTOR=mock   # default, no DC needed
ADSHIELD_AD_CONNECTOR=real   # ldap3 over LDAPS
```

**RealADConnector** — LDAPS with `CERT_REQUIRED` outside dev, paged searches, `userAccountControl` flag decoding, `objectSid` binary→string conversion, nested group expansion via `LDAP_MATCHING_RULE_IN_CHAIN`, RFC-4515 filter escaping (LDAP injection defence), and `nTSecurityDescriptor` DACL parsing into `GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `AddMember`, `ForceChangePassword`, and `HasDCSync` edges (DCSync = both replication GUIDs present).

**Least privilege** — the service account binds `read_only=True` and only needs *Read* on the domain NC plus *Read Security* to fetch `nTSecurityDescriptor`. It is never used to authenticate end users: each login opens its own short-lived bind connection that is unbound in a `finally` block.

**Auth + RBAC** — `POST /auth/login` binds the user's own credentials to the DC, resolves nested group membership → `Role`, and issues a JWT (`iss`/`aud`/`exp`/`jti`, HS256, required claims enforced on decode). Passwords are never stored, cached, or logged; failed logins log username + IP only and never distinguish unknown-user from wrong-password. Roles map to a `Permission` set (`ROLE_PERMISSIONS`), and routers gate with `RequireAssets` / `RequireFindings` / `RequireAttackPaths` / `RequireSecurityAdmin`.

| Role | AD groups | Can see |
|---|---|---|
| `standard_user` | (default) | own hygiene, own risk score, submit samples |
| `it_support` | `ADShield-Helpdesk` | + asset inventory, malware verdicts |
| `security_admin` | `ADShield-SOC`, Domain/Enterprise Admins | everything |

### Run the mock backend
```bash
cd backend && pip install -r requirements.txt
export ADSHIELD_JWT_SECRET="$(openssl rand -hex 32)"
uvicorn app.main:app --reload      # app/main.py lands in Phase 3
```
Mock logins: `j.doe` (standard), `h.desk` (IT), `t.admin` (SOC) — all `Password123!`.
