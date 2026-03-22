# Vantage

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Easy
**Status:** Active

## Overview

This challenge provides two pcap files captured from a cloud infrastructure environment running OpenStack. The scenario involves investigating an attack against a web server and its associated OpenStack controller node. The attacker performed web fuzzing to discover a Horizon dashboard, brute-forced admin credentials, exfiltrated API credentials and sensitive user data via the Swift object storage service, and established persistence by creating a new admin-privileged account.

## Attack Chain

```
Web fuzzing with ffuf → discover cloud.vantage.tech Horizon dashboard
  → Brute-force admin login (3 failed attempts)
    → Download OpenRC file (API credentials)
      → Authenticate to OpenStack Keystone API
        → Enumerate Swift containers → exfiltrate user data
          → Create admin user "jellibean" for persistence
```

## Evidence Files

| File | Description |
|------|-------------|
| `web-server.2025-07-01.pcap` | Traffic captured on the web server (Horizon dashboard) |
| `controller.2025-07-01.pcap` | Traffic captured on the OpenStack controller node (API) |

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | Pcap analysis, protocol hierarchy, conversation analysis, HTTP stream following |

## Methodology

### Step 1: Identify the Attacker and Attack Surface

Opening the web server pcap and examining **Statistics > Conversations** reveals one dominant conversation: `117.200.21.26` (attacker) and `157.230.81.229` (web server) exchanging ~21,000 packets — far above any other pair.

Filtering for HTTP requests from the attacker shows an initial port scan hitting every port. The **User-Agent** header on these requests identifies the tool:

```
ffuf/2.1.0
```

### Step 2: Identify the Discovered Subdomain

After the port scan, the attacker's HTTP requests target a specific virtual host. The **Host** header in requests to `/dashboard/` reveals the discovered subdomain:

```
Host: cloud.vantage.tech
```

This is an OpenStack Horizon dashboard.

### Step 3: Analyze Login Attempts

Filtering for POST requests to the login endpoint:

```
http.request.method == POST && http.request.uri contains "login"
```

Four POST requests to `/dashboard/auth/login/` are visible. Examining the HTTP response to each:
- A `302` redirect to `/dashboard/auth/login/` indicates a **failed** login
- A `302` redirect to `/dashboard/` indicates a **successful** login

**3 failed attempts** before the successful login with credentials:
- **Username:** `admin`
- **Password:** `StrongAdminSecret`
- **Region:** `default`

### Step 4: OpenRC File Download

After authenticating, the attacker browses the dashboard and downloads the OpenStack API remote access configuration file:

```
GET /dashboard/project/api_access/openrc/ HTTP/1.1
```

**Timestamp:** `2025-07-01 09:40:29 UTC`

### Step 5: First API Interaction on Controller

Switching to the controller pcap, the attacker uses the stolen credentials via the OpenStack SDK to interact with the API directly. The User-Agent confirms CLI usage:

```
User-Agent: openstacksdk/4.6.0 keystoneauth1/5.11.1 python-requests/2.32.4 CPython/3.13.5
```

The first API request (a GET to `/identity`) occurs at **`2025-07-01 09:41:44 UTC`**.

### Step 6: Keystone Authentication and Project ID

The attacker authenticates to the Keystone identity service by POSTing to `/identity/v3/auth/tokens` with the `admin` credentials. The response contains the token, service catalog, and project details:

```json
"project": {
    "domain": {"id": "default", "name": "Default"},
    "id": "9fb84977ff7c4a0baf0d5dbb57e235c7",
    "name": "admin"
}
```

**Authentication/authorization service:** Keystone (`type: identity`)

### Step 7: Swift Object Storage Enumeration

The service catalog in the auth response reveals the Swift endpoint:

```
http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7
```

The attacker lists all containers with a GET to the Swift endpoint. The response header `X-Account-Container-Count: 3` and body confirm **3 containers**:

| Container | Description |
|-----------|-------------|
| `dev-files` | Empty |
| `employee-data` | Contains `employee-details.csv` |
| `user-data` | Contains `user-details.csv` |

### Step 8: Sensitive Data Exfiltration

The attacker downloads the user data file:

```
GET /v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7/user-data/user-details.csv HTTP/1.1
```

**Timestamp:** `2025-07-01 09:45:23 UTC`

The file contains **28 user records** (Full Name, Email, Phone Number).

### Step 9: Persistence via Account Creation

The attacker creates a new user with admin privileges via the Keystone API:

```
POST /identity/v3/users
```

- **Username:** `jellibean`
- **Password:** `P@$$word`

**MITRE ATT&CK:** T1136.003 — Create Account: Cloud Account

## Key Takeaways

**Protocol hierarchy guides your analysis** — Starting with Wireshark's Statistics > Protocol Hierarchy and Conversations views immediately identifies the dominant traffic flows and protocols, letting you focus on what matters rather than drowning in packets.

**HTTP response codes tell the story** — Distinguishing failed login attempts (302 to login page) from successful ones (302 to dashboard) is a fundamental pattern for detecting brute-force attacks in web traffic.

**Service catalogs are a roadmap** — The OpenStack Keystone token response contains the full service catalog with every endpoint URL. In an investigation, this single response maps out the attacker's entire potential attack surface.

**Object storage is a high-value target** — Swift containers with permissive ACLs (`X-Container-Read: .r:*,.rlistings`) allowed the attacker to enumerate and exfiltrate data. Cloud storage access controls should be audited regularly.

**Cloud account creation is a persistence technique** — Creating a new admin user (T1136.003) provides the attacker with a backdoor that survives password resets on the compromised account. Monitor identity services for unexpected user creation events.
