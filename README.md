# Shielded Domain

# Role and Objective

Act as a Senior Cybersecurity Architect and Full-Stack Principal Engineer. Your task is to build "ADShield," an enterprise-grade Active Directory Security Assessment and Attack-Path Analysis platform. 

This is a final-year cybersecurity project. It must feature production-ready architecture, secure coding practices, and a highly polished, SOC-style dark theme UI.

# Core Tech Stack

*   **Frontend:** React 18, TypeScript, Vite, Tailwind CSS (Strict dark mode), React Router, Cytoscape.js (for attack path graphs), Recharts (for dashboards).

*   **Backend:** Python 3.11+, FastAPI, SQLAlchemy (PostgreSQL), Pydantic.

*   **Directory/Security:** `ldap3` (for real AD connection), PyJWT (for session management).

# 1. Seamless Active Directory & Connector Architecture

The system must be designed to switch between a `MockADConnector` (for immediate UI/UX development) and a `RealADConnector` without changing any backend business logic or frontend code.

*   Implement a base `ADConnector` abstract class.

*   The `RealADConnector` must use the `ldap3` Python library to securely connect via LDAPS.

*   It must read AD objects (Users, Groups, Computers, GPOs) and extract ACLs/ACEs to build relationships (e.g., MemberOf, HasDCSync, WriteDacl) for attack path analysis.

*   Service accounts must follow the principle of least privilege.

# 2. Domain-Wide RBAC & Authentication

The platform must be accessible to all users on the domain, using their actual AD credentials to log in. 

*   **Authentication:** FastAPI must validate credentials against the Domain Controller (via LDAP bind). If successful, issue a JWT.

*   **Role-Based Access Control (RBAC):**

    *   **Standard Users:** Can log in to view their own security hygiene (password age, groups they belong to) and a personalized "Risk Score." They cannot see domain-wide vulnerabilities.

    *   **IT/Helpdesk:** Can view user and computer assets, but cannot access deep attack-path graphs or raw vulnerability findings.

    *   **Security Admins (SOC):** Full access to domain-wide dashboards, attack paths, malware analysis, and reporting.

# 3. Endpoint Malware Verification API (New Feature)

ADShield must serve as a centralized malware analysis engine for the domain.

*   Create a dedicated `/api/endpoint/scan-file` route.

*   This endpoint will accept a file hash (SHA-256) or a binary payload from domain endpoints (simulated via a PowerShell watcher script on the workstations).

*   The backend should check the file against a local static analysis engine (PE structure, YARA rules, Entropy) and return a `{ "status": "CLEAN" | "MALICIOUS", "risk_score": 85 }` response.

# 4. Attack Path Engine

*   The backend must process AD relationships into a graph structure (Nodes = Principals/Computers, Edges = Permissions/Access).

*   Create an algorithm (e.g., Dijkstra's or BFS) to find the shortest path from a compromised standard user to Domain Admins or a Domain Controller.

*   The frontend must render this visually using Cytoscape.js, allowing the user to click nodes to see exact permission abuses (e.g., "GenericAll").

# 5. UI/UX Requirements

*   No gaming aesthetics. Use a professional SOC color palette (Slate backgrounds, subtle borders, traffic-light severity colors: Red=Critical, Orange=High, Yellow=Medium, Green=Low).

*   Include loading skeletons, error boundaries, and toast notifications.

*   All data tables must have global search, column filtering, and pagination.

# Execution Instructions for the AI:

Do not write the entire application at once. Let's build it systematically.

1.  **Phase 1:** Start by providing the exact directory structure for both the FastAPI backend and the React frontend.

2.  **Phase 2:** Write the Base Connector Interface and the Active Directory Authentication/RBAC logic in FastAPI.

3.  **Phase 3:** Await my confirmation before moving to the frontend scaffolding and database schemas.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/1e7fd9b1-b51c-4879-b254-85829066f66e).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
